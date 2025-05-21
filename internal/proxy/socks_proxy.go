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
	var backendInstance *torinstance.Instance // To store the chosen instance for decrementing later
	defer func() {
		clientConn.Close()
		if backendInstance != nil { // Ensure backendInstance was successfully assigned
			backendInstance.DecrementActiveProxyConnections()
			// log.Printf("SOCKS: Decremented active conns for instance %d. Now: %d", backendInstance.InstanceID, backendInstance.GetActiveProxyConnections())
		}
	}()

	clientConn.SetReadDeadline(time.Now().Add(appCfg.SocksTimeout))

	buf := make([]byte, 260)
	n, err := clientConn.Read(buf)
	if err != nil {
		// No need to log EOF as it's a common way for connections to close
		if err != io.EOF {
			// log.Printf("SOCKS: Initial read error from %s: %v", clientConn.RemoteAddr(), err)
		}
		return
	}
	clientConn.SetReadDeadline(time.Time{})

	if n < 2 {
		// log.Printf("SOCKS: Short initial read (%d bytes) from %s", n, clientConn.RemoteAddr())
		return
	}

	version := buf[0]
	nmethods := buf[1]
	if version != 5 {
		log.Printf("SOCKS: Unsupported version %d from %s", version, clientConn.RemoteAddr())
		return
	}
	if n < 2+int(nmethods) {
		// log.Printf("SOCKS: Short read for methods list (%d bytes, expected %d) from %s", n, 2+int(nmethods), clientConn.RemoteAddr())
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
		clientConn.Write([]byte{0x05, 0xFF}) // METHOD NOT ACCEPTED
		return
	}
	clientConn.Write([]byte{0x05, 0x00}) // Select NO AUTHENTICATION

	clientConn.SetReadDeadline(time.Now().Add(appCfg.SocksTimeout))
	n, err = clientConn.Read(buf)
	if err != nil {
		if err != io.EOF {
			// log.Printf("SOCKS: Request read error from %s: %v", clientConn.RemoteAddr(), err)
		}
		return
	}
	clientConn.SetReadDeadline(time.Time{})

	if n < 7 { // Minimum SOCKS request: VER CMD RSV ATYP DST.ADDR (1 byte IP) DST.PORT (2 bytes)
		// log.Printf("SOCKS: Short request read (%d bytes) from %s", n, clientConn.RemoteAddr())
		return
	}

	cmd := buf[1]
	atyp := buf[3]

	if cmd != 1 { // CONNECT
		log.Printf("SOCKS: Unsupported command %d from %s", cmd, clientConn.RemoteAddr())
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // COMMAND NOT SUPPORTED
		return
	}

	var targetHost string
	var targetPort uint16
	offset := 4

	switch atyp {
	case 1: // IPv4
		if n < offset+net.IPv4len+2 {
			return
		}
		targetHost = net.IP(buf[offset : offset+net.IPv4len]).String()
		offset += net.IPv4len
	case 3: // Domain name
		domainLen := int(buf[offset])
		offset++
		if n < offset+domainLen+2 {
			return
		}
		targetHost = string(buf[offset : offset+domainLen])
		offset += domainLen
	case 4: // IPv6
		if n < offset+net.IPv6len+2 {
			return
		}
		targetHost = net.IP(buf[offset : offset+net.IPv6len]).String()
		offset += net.IPv6len
	default:
		log.Printf("SOCKS: Unsupported address type %d from %s", atyp, clientConn.RemoteAddr())
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // ADDRESS TYPE NOT SUPPORTED
		return
	}
	targetPort = uint16(buf[offset])<<8 | uint16(buf[offset+1])
	targetAddress := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	chosenInstance, errLb := lb.GetNextHealthyInstance(instances, appCfg)
	if errLb != nil {
		log.Printf("SOCKS: No healthy backend Tor for %s to %s: %v", clientConn.RemoteAddr(), targetAddress, errLb)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // GENERAL SERVER FAILURE
		return
	}
	backendInstance = chosenInstance // Assign for the defer
	backendInstance.IncrementActiveProxyConnections()
	// log.Printf("SOCKS: Incremented active conns for instance %d. Now: %d", backendInstance.InstanceID, backendInstance.GetActiveProxyConnections())


	dialer, err := proxy.SOCKS5("tcp", backendInstance.BackendSocksHost, nil, &net.Dialer{Timeout: appCfg.SocksTimeout})
	if err != nil {
		log.Printf("SOCKS: Failed to create SOCKS5 dialer for backend Tor %s: %v", backendInstance.BackendSocksHost, err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return // Decrement will be handled by defer
	}

	targetTCPConn, err := dialer.Dial("tcp", targetAddress)
	if err != nil {
		log.Printf("SOCKS: Tor %s (inst %d, %d conns) failed for client %s to target %s: %v",
			backendInstance.BackendSocksHost, backendInstance.InstanceID, backendInstance.GetActiveProxyConnections(),
			clientConn.RemoteAddr(), targetAddress, err)
		replyCode := byte(0x01) // GENERAL SERVER FAILURE
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			replyCode = 0x06 // TTL EXPIRED (interpreted as timeout)
		} else if strings.Contains(strings.ToLower(err.Error()), "refused") {
			replyCode = 0x05 // CONNECTION REFUSED
		} else if strings.Contains(strings.ToLower(err.Error()), "no route") || strings.Contains(strings.ToLower(err.Error()), "unreachable") {
			replyCode = 0x03 // NETWORK UNREACHABLE
		} else if strings.Contains(strings.ToLower(err.Error()), "host unreachable") {
			replyCode = 0x04 // HOST UNREACHABLE
		}
		clientConn.Write([]byte{0x05, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return // Decrement will be handled by defer
	}
	defer targetTCPConn.Close()

	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // SUCCEEDED

	errChan := make(chan error, 2)
	copyData := func(dst io.WriteCloser, src io.ReadCloser, dstName, srcName string) {
		// Close the Read side of the connection when copying is done or an error occurs.
		// This helps signal the other copy goroutine if one side closes.
		defer func() {
			if c, ok := src.(interface{ CloseRead() error }); ok {
				c.CloseRead()
			}
			// For net.TCPConn, CloseWrite() can also be used to signal EOF.
			// if c, ok := dst.(interface{ CloseWrite() error }); ok {
			// 	c.CloseWrite()
			// }
		}()
		_, copyErr := io.Copy(dst, src)
		errChan <- copyErr
	}

	go copyData(targetTCPConn, clientConn, "target", "client")
	go copyData(clientConn, targetTCPConn, "client", "target")

	// Wait for one of the copy operations to finish or error out.
	// The other will likely finish soon after due to EOF or error.
	<-errChan
	// Optionally wait for the second one or just let the defers handle cleanup.
	// <-errChan
}

func StartSocksProxyServer(instances []*torinstance.Instance, appCfg *config.AppConfig) {
	listenAddr := "0.0.0.0:" + appCfg.CommonSocksPort
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to start SOCKS5 proxy server on %s: %v", listenAddr, err)
	}
	defer listener.Close()
	log.Printf("SOCKS5 proxy server listening on %s (LB to backend Tor instances, strategy: %s)", listenAddr, appCfg.LoadBalancingStrategy)

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
