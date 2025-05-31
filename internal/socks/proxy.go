package socks

import (
	"context"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy" // SOCKS5 client functionality
	"torgo/internal/config"
	"torgo/internal/lb"
	"torgo/internal/tor"
)

func handleSocksConnection(clientConn net.Conn, instances []*tor.Instance, appCfg *config.AppConfig) {
	defer clientConn.Close()

	// Set initial read deadline for SOCKS handshake
	if err := clientConn.SetReadDeadline(time.Now().Add(appCfg.SocksTimeout)); err != nil {
		// log.Printf("SOCKS: Error setting read deadline for %s: %v", clientConn.RemoteAddr(), err)
		return
	}

	// SOCKS5 Version and Method Negotiation
	buf := make([]byte, 260) // Max SOCKS request size is typically around 260 bytes
	n, err := clientConn.Read(buf)
	if err != nil {
		// if err != io.EOF { log.Printf("SOCKS: Handshake read error from %s: %v", clientConn.RemoteAddr(), err) }
		return
	}

	if n < 2 {
		// log.Printf("SOCKS: Short read during handshake from %s (%d bytes)", clientConn.RemoteAddr(), n)
		return
	}

	version := buf[0]
	nmethods := buf[1]

	if version != 5 { // SOCKS5
		log.Printf("SOCKS: Unsupported version %d from %s", version, clientConn.RemoteAddr())
		return
	}
	if n < 2+int(nmethods) {
		// log.Printf("SOCKS: Short read for methods from %s", clientConn.RemoteAddr())
		return
	}

	clientSupportsNoAuth := false
	for _, method := range buf[2 : 2+int(nmethods)] {
		if method == 0x00 { // NO AUTHENTICATION REQUIRED
			clientSupportsNoAuth = true
			break
		}
	}

	if !clientSupportsNoAuth {
		log.Printf("SOCKS: Client %s does not support NO AUTHENTICATION (0x00) method.", clientConn.RemoteAddr())
		clientConn.Write([]byte{0x05, 0xFF}) // VERSION 5, NO ACCEPTABLE METHODS
		return
	}

	// Send NO AUTHENTICATION REQUIRED response
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		// log.Printf("SOCKS: Error writing auth method response to %s: %v", clientConn.RemoteAddr(), err)
		return
	}

	// Read SOCKS5 request
	if err := clientConn.SetReadDeadline(time.Now().Add(appCfg.SocksTimeout)); err != nil {
		// log.Printf("SOCKS: Error setting read deadline for request from %s: %v", clientConn.RemoteAddr(), err)
		return
	}
	n, err = clientConn.Read(buf)
	if err != nil {
		// if err != io.EOF { log.Printf("SOCKS: Request read error from %s: %v", clientConn.RemoteAddr(), err) }
		return
	}

	if n < 7 { // VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(min 1) DST.PORT(2)
		// log.Printf("SOCKS: Short read for request details from %s (%d bytes)", clientConn.RemoteAddr(), n)
		return
	}

	cmd := buf[1]
	atyp := buf[3]

	if cmd != 1 { // CONNECT command
		log.Printf("SOCKS: Unsupported command 0x%02x from %s. Only CONNECT (0x01) is supported.", cmd, clientConn.RemoteAddr())
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
		return
	}

	var targetHost string
	var targetPort uint16
	addrCursor := 4

	switch atyp {
	case 1: // IPv4 address
		if n < addrCursor+net.IPv4len+2 { return }
		targetHost = net.IP(buf[addrCursor : addrCursor+net.IPv4len]).String()
		addrCursor += net.IPv4len
	case 3: // Domain name
		domainLen := int(buf[addrCursor])
		addrCursor++
		if n < addrCursor+domainLen+2 { return }
		targetHost = string(buf[addrCursor : addrCursor+domainLen])
		addrCursor += domainLen
	case 4: // IPv6 address
		if n < addrCursor+net.IPv6len+2 { return }
		targetHost = net.IP(buf[addrCursor : addrCursor+net.IPv6len]).String()
		addrCursor += net.IPv6len
	default:
		log.Printf("SOCKS: Unsupported address type 0x%02x from %s", atyp, clientConn.RemoteAddr())
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return
	}

	if n < addrCursor+2 { return } // Ensure port bytes are available
	targetPort = uint16(buf[addrCursor])<<8 | uint16(buf[addrCursor+1])
	targetAddress := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	clientConn.SetReadDeadline(time.Time{}) // Clear read deadline for data transfer phase

	backendInstance, err := lb.GetNextHealthyInstance(instances)
	if err != nil {
		log.Printf("SOCKS: No healthy backend Tor for client %s to target %s: %v", clientConn.RemoteAddr(), targetAddress, err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // General SOCKS server failure
		return
	}

	dialer, err := proxy.SOCKS5("tcp", backendInstance.GetBackendSocksHost(), nil, &net.Dialer{
		Timeout: appCfg.SocksTimeout,
	})
	if err != nil {
		log.Printf("SOCKS: Failed to create SOCKS5 dialer for backend Tor %s (instance %d): %v", backendInstance.GetBackendSocksHost(), backendInstance.InstanceID, err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	targetTCPConn, err := dialer.Dial("tcp", targetAddress)
	if err != nil {
		replyCode := byte(0x01)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() { replyCode = 0x06
		} else if strings.Contains(strings.ToLower(err.Error()), "refused") { replyCode = 0x05
		} else if strings.Contains(strings.ToLower(err.Error()), "unreachable") { replyCode = 0x03
		} else if strings.Contains(strings.ToLower(err.Error()), "host unreachable") { replyCode = 0x04 }
		clientConn.Write([]byte{0x05, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetTCPConn.Close()

	if _, err := clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	errChan := make(chan error, 2)
	copyData := func(dst io.WriteCloser, src io.ReadCloser) {
		_, copyErr := io.Copy(dst, src)
		if tcpDst, ok := dst.(*net.TCPConn); ok { tcpDst.CloseWrite() }
		if tcpSrc, ok := src.(*net.TCPConn); ok { tcpSrc.CloseRead() }
		errChan <- copyErr
	}

	go copyData(targetTCPConn, clientConn)
	go copyData(clientConn, targetTCPConn)

	for i := 0; i < 2; i++ {
		<-errChan // Wait for both copy operations to finish
	}
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
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}
			break 
		}
		go handleSocksConnection(conn, instances, appCfg)
	}
	log.Println("SOCKS Proxy: Server has shut down.")
}
