package socks

import (
	"context"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"golang.org/x/net/proxy"
	"torgo/internal/config"
	"torgo/internal/lb"
	"torgo/internal/tor"
)

func handleSocksConnection(clientConn net.Conn, instances []*tor.Instance, appCfg *config.AppConfig) {
	defer clientConn.Close()

	backendInstance, err := lb.GetNextHealthyInstance(instances)
	if err != nil {
		log.Printf("SOCKS: No healthy backend Tor for client %s: %v", clientConn.RemoteAddr(), err)
		return
	}

	backendInstance.IncrementActiveConnections()
	defer backendInstance.DecrementActiveConnections()

	if err := clientConn.SetReadDeadline(time.Now().Add(appCfg.SocksTimeout)); err != nil {
		return
	}

	buf := make([]byte, 260)
	n, err := clientConn.Read(buf)
	if err != nil {
		return
	}

	if n < 2 || buf[0] != 5 {
		return
	}

	nmethods := buf[1]
	if n < 2+int(nmethods) {
		return
	}

	clientSupportsNoAuth := false
	for _, method := range buf[2 : 2+int(nmethods)] {
		if method == 0x00 {
			clientSupportsNoAuth = true
			break
		}
	}

	if !clientSupportsNoAuth {
		clientConn.Write([]byte{0x05, 0xFF})
		return
	}

	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(appCfg.SocksTimeout)); err != nil {
		return
	}
	n, err = clientConn.Read(buf)
	if err != nil {
		return
	}

	if n < 7 || buf[1] != 1 {
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetHost string
	addrCursor := 4
	switch buf[3] {
	case 1: // IPv4
		if n < addrCursor+net.IPv4len+2 {
			return
		}
		targetHost = net.IP(buf[addrCursor : addrCursor+net.IPv4len]).String()
		addrCursor += net.IPv4len
	case 3: // Domain
		domainLen := int(buf[addrCursor])
		addrCursor++
		if n < addrCursor+domainLen+2 {
			return
		}
		targetHost = string(buf[addrCursor : addrCursor+domainLen])
		addrCursor += domainLen
	case 4: // IPv6
		if n < addrCursor+net.IPv6len+2 {
			return
		}
		targetHost = net.IP(buf[addrCursor : addrCursor+net.IPv6len]).String()
		addrCursor += net.IPv6len
	default:
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	targetPort := uint16(buf[addrCursor])<<8 | uint16(buf[addrCursor+1])
	targetAddress := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	clientConn.SetReadDeadline(time.Time{})

	dialer, err := proxy.SOCKS5("tcp", backendInstance.GetBackendSocksHost(), nil, &net.Dialer{
		Timeout: appCfg.SocksTimeout,
	})
	if err != nil {
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	targetTCPConn, err := dialer.Dial("tcp", targetAddress)
	if err != nil {
		replyCode := byte(0x01)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			replyCode = 0x06
		}
		clientConn.Write([]byte{0x05, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetTCPConn.Close()

	if _, err := clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	errChan := make(chan error, 2)
	go func() { _, err := io.Copy(targetTCPConn, clientConn); errChan <- err }()
	go func() { _, err := io.Copy(clientConn, targetTCPConn); errChan <- err }()
	<-errChan
	<-errChan
}

func StartSocksProxyServer(ctx context.Context, instances []*tor.Instance, appCfg *config.AppConfig) {
	listenAddr := "0.0.0.0:" + appCfg.CommonSocksPort
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("SOCKS: Failed to start SOCKS5 proxy server on %s: %v", listenAddr, err)
	}
	log.Printf("SOCKS5 proxy server listening on %s", listenAddr)

	go func() {
		<-ctx.Done()
		log.Println("SOCKS Proxy: Shutting down SOCKS listener...")
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				log.Println("SOCKS Proxy: Listener closed as part of shutdown.")
			default:
				log.Printf("SOCKS: Failed to accept connection: %v", err)
			}
			break
		}
		go handleSocksConnection(conn, instances, appCfg)
	}
	log.Println("SOCKS Proxy: Server has shut down.")
}