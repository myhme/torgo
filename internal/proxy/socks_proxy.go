package proxy

import (
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
	"torgo/internal/config"
	"torgo/internal/lb"
	"torgo/internal/torinstance"
)

func handleSocksConnection(clientConn net.Conn, instances []*torinstance.Instance, appCfg *config.AppConfig) {
	defer clientConn.Close()
	clientConn.SetReadDeadline(time.Now().Add(appCfg.SocksTimeout))

	buf := make([]byte, 260) 
	n, err := clientConn.Read(buf)
	if err != nil {
		if err != io.EOF { 
		}
		return
	}
	clientConn.SetReadDeadline(time.Time{}) 

	if n < 2 {
		return
	}

	version := buf[0]
	nmethods := buf[1]
	if version != 5 {
		log.Printf("SOCKS: Unsupported version %d from %s", version, clientConn.RemoteAddr())
		return
	}
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
		log.Printf("SOCKS: Client %s does not support NO AUTHENTICATION method.", clientConn.RemoteAddr())
		clientConn.Write([]byte{0x05, 0xFF}) 
		return
	}
	clientConn.Write([]byte{0x05, 0x00}) 

	clientConn.SetReadDeadline(time.Now().Add(appCfg.SocksTimeout))
	n, err = clientConn.Read(buf)
	if err != nil {
		if err != io.EOF {
		}
		return
	}
	clientConn.SetReadDeadline(time.Time{})

	if n < 7 { 
		return
	}

	cmd := buf[1]
	atyp := buf[3]

	if cmd != 1 { 
		log.Printf("SOCKS: Unsupported command %d from %s", cmd, clientConn.RemoteAddr())
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) 
		return
	}

	var targetHost string
	var targetPort uint16
	offset := 4

	switch atyp {
	case 1: 
		if n < offset+net.IPv4len+2 { return }
		targetHost = net.IP(buf[offset : offset+net.IPv4len]).String()
		offset += net.IPv4len
	case 3: 
		domainLen := int(buf[offset])
		offset++
		if n < offset+domainLen+2 { return }
		targetHost = string(buf[offset : offset+domainLen])
		offset += domainLen
	case 4: 
		if n < offset+net.IPv6len+2 { return }
		targetHost = net.IP(buf[offset : offset+net.IPv6len]).String()
		offset += net.IPv6len
	default:
		log.Printf("SOCKS: Unsupported address type %d from %s", atyp, clientConn.RemoteAddr())
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) 
		return
	}
	targetPort = uint16(buf[offset])<<8 | uint16(buf[offset+1])
	targetAddress := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	backendInstance, err := lb.GetNextHealthyInstance(instances) // appCfg removed
	if err != nil {
		log.Printf("SOCKS: No healthy backend Tor for %s to %s: %v", clientConn.RemoteAddr(), targetAddress, err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) 
		return
	}

	dialer, err := proxy.SOCKS5("tcp", backendInstance.BackendSocksHost, nil, &net.Dialer{Timeout: appCfg.SocksTimeout})
	if err != nil {
		log.Printf("SOCKS: Failed to create SOCKS5 dialer for backend Tor %s: %v", backendInstance.BackendSocksHost, err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	targetTCPConn, err := dialer.Dial("tcp", targetAddress)
	if err != nil {
		log.Printf("SOCKS: Tor %s (inst %d) failed to connect client %s to target %s: %v", backendInstance.BackendSocksHost, backendInstance.InstanceID, clientConn.RemoteAddr(), targetAddress, err)
		replyCode := byte(0x01) 
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			replyCode = 0x06 
		} else if strings.Contains(strings.ToLower(err.Error()), "refused") {
			replyCode = 0x05 
		} else if strings.Contains(strings.ToLower(err.Error()), "no route") || strings.Contains(strings.ToLower(err.Error()), "unreachable") {
			replyCode = 0x03 
		} else if strings.Contains(strings.ToLower(err.Error()), "host unreachable"){
			replyCode = 0x04 
		}
		clientConn.Write([]byte{0x05, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetTCPConn.Close()

	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) 
	
	errChan := make(chan error, 2)
	copyData := func(dst io.WriteCloser, src io.ReadCloser, dstName, srcName string) {
		defer func() {
			if c, ok := src.(interface{ CloseRead() error }); ok {
				c.CloseRead()
			} 
		}()
		_, copyErr := io.Copy(dst, src)
		errChan <- copyErr
	}

	go copyData(targetTCPConn, clientConn, "target", "client")
	go copyData(clientConn, targetTCPConn, "client", "target")
	
	<-errChan
}

func StartSocksProxyServer(instances []*torinstance.Instance, appCfg *config.AppConfig) {
	listenAddr := "0.0.0.0:" + appCfg.CommonSocksPort
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to start SOCKS5 proxy server on %s: %v", listenAddr, err)
	}
	defer listener.Close()
	log.Printf("SOCKS5 proxy server listening on %s (LB to backend Tor instances)", listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				log.Printf("SOCKS5 server temporary accept error: %v; retrying...", err)
				time.Sleep(time.Millisecond * 100) 
				continue
			}
			log.Printf("SOCKS5 server failed to accept connection (or listener closed): %v", err)
			return 
		}
		go handleSocksConnection(conn, instances, appCfg)
	}
}
