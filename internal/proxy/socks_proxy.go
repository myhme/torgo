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

	buf := make([]byte, 260) // SOCKS header + address
	n, err := clientConn.Read(buf)
	if err != nil {
		if err != io.EOF { // Don't log EOF as a verbose error if client just closed
			// log.Printf("SOCKS: Error reading version/nmethods from %s: %v", clientConn.RemoteAddr(), err)
		}
		return
	}
	clientConn.SetReadDeadline(time.Time{}) // Clear deadline after successful read

	if n < 2 {
		// log.Printf("SOCKS: Short read for version/nmethods from %s (got %d bytes)", clientConn.RemoteAddr(), n)
		return
	}

	version := buf[0]
	nmethods := buf[1]
	if version != 5 {
		log.Printf("SOCKS: Unsupported version %d from %s", version, clientConn.RemoteAddr())
		return
	}
	if n < 2+int(nmethods) {
		// log.Printf("SOCKS: Short read for methods from %s (expected %d, got %d)", clientConn.RemoteAddr(), 2+int(nmethods), n)
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
		log.Printf("SOCKS: Client %s does not support NO AUTHENTICATION method.", clientConn.RemoteAddr())
		clientConn.Write([]byte{0x05, 0xFF}) // No acceptable methods
		return
	}
	clientConn.Write([]byte{0x05, 0x00}) // VER 5, METHOD NO AUTH (0x00)

	clientConn.SetReadDeadline(time.Now().Add(appCfg.SocksTimeout))
	n, err = clientConn.Read(buf)
	if err != nil {
		if err != io.EOF {
			// log.Printf("SOCKS: Error reading request from %s: %v (read %d bytes)", clientConn.RemoteAddr(), err, n)
		}
		return
	}
	clientConn.SetReadDeadline(time.Time{})

	if n < 7 { // VER, CMD, RSV, ATYP, DST.ADDR (min 1 byte for domain len or IPv4), DST.PORT (2 bytes)
		// log.Printf("SOCKS: Short read for request from %s (got %d bytes)", clientConn.RemoteAddr(), n)
		return
	}

	cmd := buf[1]
	atyp := buf[3]

	if cmd != 1 { // CMD_CONNECT
		log.Printf("SOCKS: Unsupported command %d from %s", cmd, clientConn.RemoteAddr())
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported
		return
	}

	var targetHost string
	var targetPort uint16
	offset := 4

	switch atyp {
	case 1: // IPv4 address
		if n < offset+net.IPv4len+2 { /*log.Printf("SOCKS: Short read for IPv4 addr/port from %s", clientConn.RemoteAddr());*/ return }
		targetHost = net.IP(buf[offset : offset+net.IPv4len]).String()
		offset += net.IPv4len
	case 3: // Domain name
		domainLen := int(buf[offset])
		offset++
		if n < offset+domainLen+2 { /*log.Printf("SOCKS: Short read for domain name/port from %s", clientConn.RemoteAddr());*/ return }
		targetHost = string(buf[offset : offset+domainLen])
		offset += domainLen
	case 4: // IPv6 address
		if n < offset+net.IPv6len+2 { /*log.Printf("SOCKS: Short read for IPv6 addr/port from %s", clientConn.RemoteAddr());*/ return }
		targetHost = net.IP(buf[offset : offset+net.IPv6len]).String()
		offset += net.IPv6len
	default:
		log.Printf("SOCKS: Unsupported address type %d from %s", atyp, clientConn.RemoteAddr())
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return
	}
	targetPort = uint16(buf[offset])<<8 | uint16(buf[offset+1])
	targetAddress := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	backendInstance, err := lb.GetNextHealthyInstance(instances, appCfg)
	if err != nil {
		log.Printf("SOCKS: No healthy backend Tor for %s to %s: %v", clientConn.RemoteAddr(), targetAddress, err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // General SOCKS server failure
		return
	}

	// Use the instance's specific SOCKS port for the backend connection
	dialer, err := proxy.SOCKS5("tcp", backendInstance.BackendSocksHost, nil, &net.Dialer{Timeout: appCfg.SocksTimeout})
	if err != nil {
		log.Printf("SOCKS: Failed to create SOCKS5 dialer for backend Tor %s: %v", backendInstance.BackendSocksHost, err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	targetTCPConn, err := dialer.Dial("tcp", targetAddress)
	if err != nil {
		log.Printf("SOCKS: Tor %s (inst %d) failed to connect client %s to target %s: %v", backendInstance.BackendSocksHost, backendInstance.InstanceID, clientConn.RemoteAddr(), targetAddress, err)
		replyCode := byte(0x01) // General server failure
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			replyCode = 0x06 // TTL expired (used for connection timeout)
		} else if strings.Contains(strings.ToLower(err.Error()), "refused") {
			replyCode = 0x05 // Connection refused
		} else if strings.Contains(strings.ToLower(err.Error()), "no route") || strings.Contains(strings.ToLower(err.Error()), "unreachable") {
			replyCode = 0x03 // Network unreachable
		} else if strings.Contains(strings.ToLower(err.Error()), "host unreachable"){
			replyCode = 0x04 // Host unreachable
		}
		clientConn.Write([]byte{0x05, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetTCPConn.Close()

	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Success

	errChan := make(chan error, 2)
	copyData := func(dst io.WriteCloser, src io.ReadCloser, dstName, srcName string) {
		// defer log.Printf("SOCKS: Finished copying from %s to %s for %s", srcName, dstName, clientConn.RemoteAddr())
		_, copyErr := io.Copy(dst, src)
		// If src implements CloseRead, call it to signal the other direction.
		if cr, ok := src.(interface{ CloseRead() error }); ok {
			cr.CloseRead()
		}
		// If dst implements CloseWrite, call it.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		errChan <- copyErr
	}

	go copyData(targetTCPConn, clientConn, "target", "client")
	go copyData(clientConn, targetTCPConn, "client", "target")
	
	// Wait for one of the copy operations to finish or error
	<-errChan
	// Optionally wait for the second one or log which one finished/errored
	// log.Printf("SOCKS: Data proxying finished for %s to %s via Tor %s.", clientConn.RemoteAddr(), targetAddress, backendInstance.BackendSocksHost)
}

// StartSocksProxyServer starts the common SOCKS5 proxy server.
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
			// Check if the error is due to the listener being closed, e.g., during shutdown
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				log.Printf("SOCKS5 server temporary accept error: %v; retrying...", err)
				time.Sleep(time.Millisecond * 100) // Brief pause before retrying
				continue
			}
			// If it's not a temporary error, it might be serious (e.g. listener closed)
			log.Printf("SOCKS5 server failed to accept connection (or listener closed): %v", err)
			return // Exit if listener is closed
		}
		go handleSocksConnection(conn, instances, appCfg)
	}
}
