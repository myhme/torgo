package proxy

import (
	"io"
	"log/slog" // Import slog
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
	var backendInstance *torinstance.Instance 
	clientRemoteAddr := clientConn.RemoteAddr().String()

	defer func() {
		clientConn.Close()
		if backendInstance != nil { 
			backendInstance.DecrementActiveProxyConnections()
			slog.Debug("SOCKS: Connection closed, decremented active conns.", 
				"instance_id", backendInstance.InstanceID, 
				"client_addr", clientRemoteAddr,
				"active_conns_now", backendInstance.GetActiveProxyConnections())
		} else {
			slog.Debug("SOCKS: Connection closed (no backend instance assigned).", "client_addr", clientRemoteAddr)
		}
	}()

	clientConn.SetReadDeadline(time.Now().Add(appCfg.SocksTimeout))

	buf := make([]byte, 260)
	n, err := clientConn.Read(buf)
	if err != nil {
		if err != io.EOF { // EOF is normal closure
			slog.Debug("SOCKS: Initial read error from client.", "client_addr", clientRemoteAddr, slog.Any("error", err))
		}
		return
	}
	clientConn.SetReadDeadline(time.Time{})

	if n < 2 {
		slog.Debug("SOCKS: Short initial read from client.", "client_addr", clientRemoteAddr, "bytes_read", n)
		return
	}

	version := buf[0]
	nmethods := buf[1]
	if version != 5 {
		slog.Warn("SOCKS: Unsupported version from client.", "client_addr", clientRemoteAddr, "version", version)
		return
	}
	if n < 2+int(nmethods) {
		slog.Debug("SOCKS: Short read for methods list from client.", "client_addr", clientRemoteAddr, "bytes_read", n, "expected_min", 2+int(nmethods))
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
		slog.Warn("SOCKS: Client does not support NO AUTHENTICATION method.", "client_addr", clientRemoteAddr)
		clientConn.Write([]byte{0x05, 0xFF}) 
		return
	}
	clientConn.Write([]byte{0x05, 0x00}) 

	clientConn.SetReadDeadline(time.Now().Add(appCfg.SocksTimeout))
	n, err = clientConn.Read(buf)
	if err != nil {
		if err != io.EOF {
			slog.Debug("SOCKS: Request read error from client.", "client_addr", clientRemoteAddr, slog.Any("error", err))
		}
		return
	}
	clientConn.SetReadDeadline(time.Time{})

	if n < 7 { 
		slog.Debug("SOCKS: Short request read from client.", "client_addr", clientRemoteAddr, "bytes_read", n)
		return
	}

	cmd := buf[1]
	atyp := buf[3]

	if cmd != 1 { // CONNECT
		slog.Warn("SOCKS: Unsupported command from client.", "client_addr", clientRemoteAddr, "command", cmd)
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
		slog.Warn("SOCKS: Unsupported address type from client.", "client_addr", clientRemoteAddr, "address_type", atyp)
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) 
		return
	}
	targetPort = uint16(buf[offset])<<8 | uint16(buf[offset+1])
	targetAddress := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	slog.Debug("SOCKS: Received connection request.", "client_addr", clientRemoteAddr, "target_address", targetAddress)

	chosenInstance, errLb := lb.GetNextHealthyInstance(instances, appCfg)
	if errLb != nil {
		slog.Warn("SOCKS: No healthy backend Tor instance for request.", "client_addr", clientRemoteAddr, "target_address", targetAddress, slog.Any("error", errLb))
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) 
		return
	}
	backendInstance = chosenInstance 
	backendInstance.IncrementActiveProxyConnections()
	slog.Debug("SOCKS: Assigned to backend, incremented active conns.", 
		"client_addr", clientRemoteAddr,
		"target_address", targetAddress,
		"instance_id", backendInstance.InstanceID, 
		"backend_socks_host", backendInstance.BackendSocksHost,
		"active_conns_now", backendInstance.GetActiveProxyConnections())


	dialer, err := proxy.SOCKS5("tcp", backendInstance.BackendSocksHost, nil, &net.Dialer{Timeout: appCfg.SocksTimeout})
	if err != nil {
		slog.Error("SOCKS: Failed to create SOCKS5 dialer for backend Tor.", 
			"client_addr", clientRemoteAddr,
			"target_address", targetAddress,
			"instance_id", backendInstance.InstanceID, 
			"backend_socks_host", backendInstance.BackendSocksHost, 
			slog.Any("error", err))
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return 
	}

	targetTCPConn, err := dialer.Dial("tcp", targetAddress)
	if err != nil {
		slog.Warn("SOCKS: Backend Tor failed to connect to target.", 
			"client_addr", clientRemoteAddr,
			"target_address", targetAddress,
			"instance_id", backendInstance.InstanceID, 
			"backend_socks_host", backendInstance.BackendSocksHost, 
			slog.Any("error", err))
		replyCode := byte(0x01) 
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() { replyCode = 0x06 }
		if strings.Contains(strings.ToLower(err.Error()), "refused") { replyCode = 0x05 }
		if strings.Contains(strings.ToLower(err.Error()), "no route") || strings.Contains(strings.ToLower(err.Error()), "unreachable") { replyCode = 0x03 }
		if strings.Contains(strings.ToLower(err.Error()), "host unreachable"){ replyCode = 0x04 }
		clientConn.Write([]byte{0x05, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return 
	}
	defer targetTCPConn.Close()

	slog.Debug("SOCKS: Successfully connected to target via backend Tor.", 
		"client_addr", clientRemoteAddr,
		"target_address", targetAddress,
		"instance_id", backendInstance.InstanceID)
	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) 
	
	errChan := make(chan error, 2)
	copyData := func(dst io.WriteCloser, src io.ReadCloser, dstName, srcName string) {
		defer func() {
			if c, ok := src.(interface{ CloseRead() error }); ok { c.CloseRead() }
		}()
		_, copyErr := io.Copy(dst, src)
		// Don't log EOF errors from io.Copy as they are expected when a connection closes normally.
		if copyErr != nil && copyErr != io.EOF && !strings.Contains(copyErr.Error(), "use of closed network connection") {
			slog.Debug("SOCKS: Data copy error during proxying.", 
				"client_addr", clientRemoteAddr,
				"source", srcName, "destination", dstName, 
				slog.Any("error", copyErr))
		}
		errChan <- copyErr // Send error (or nil) to channel
	}

	go copyData(targetTCPConn, clientConn, "target", "client")
	go copyData(clientConn, targetTCPConn, "client", "target")
	
	<-errChan // Wait for one of the copy operations to finish or error
	slog.Debug("SOCKS: Data proxying finished for one direction.", "client_addr", clientRemoteAddr, "target_address", targetAddress)
	// The other copy will also finish due to EOF or error.
}

// StartSocksProxyServer starts the common SOCKS5 proxy server.
func StartSocksProxyServer(instances []*torinstance.Instance, appCfg *config.AppConfig) {
	listenAddr := "0.0.0.0:" + appCfg.CommonSocksPort
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		slog.Error("Failed to start SOCKS5 proxy server.", "address", listenAddr, slog.Any("error", err))
		os.Exit(1) // Critical failure
	}
	defer listener.Close()
	slog.Info("SOCKS5 proxy server listening.", "address", listenAddr, "load_balancing_strategy", appCfg.LoadBalancingStrategy)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				slog.Warn("SOCKS5 server temporary accept error, retrying.", slog.Any("error", err))
				time.Sleep(time.Millisecond * 100) 
				continue
			}
			// "use of closed network connection" is expected on shutdown.
			if !strings.Contains(err.Error(), "use of closed network connection") {
				slog.Error("SOCKS5 server failed to accept connection (or listener closed).", slog.Any("error", err))
			} else {
				slog.Info("SOCKS5 server listener closed.", slog.Any("error", err))
			}
			return 
		}
		slog.Debug("SOCKS: Accepted new client connection.", "client_addr", conn.RemoteAddr().String())
		go handleSocksConnection(conn, instances, appCfg)
	}
}
