package socks

import (
	"context"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"torgo/internal/config"
	"torgo/internal/lb"
	"torgo/internal/tor"

	"golang.org/x/net/proxy"
)

// helper: parse a comma-separated list of CIDRs
func parseCIDRs(list string) []*net.IPNet {
	var nets []*net.IPNet
	for _, s := range strings.Split(list, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

// helper: build allowed client networks (always include loopback)
func buildAllowedClientNets(lanCIDRs string) []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range []string{"127.0.0.0/8", "::1/128"} {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, n)
		}
	}
	if strings.TrimSpace(lanCIDRs) != "" {
		nets = append(nets, parseCIDRs(lanCIDRs)...)
	}
	return nets
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// helper: identify private/local/reserved ranges we don't want to proxy by default
func isPrivateOrLocalIP(ip net.IP) bool {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
	}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func handleSocksConnection(clientConn net.Conn, instances []*tor.Instance, appCfg *config.AppConfig, allowPrivateDest bool) {
	defer clientConn.Close()

	backendInstance, err := lb.GetNextHealthyInstance(instances)
	if err != nil {
		log.Printf("SOCKS: No healthy backend Tor available: %v", err)
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

	if n < 7 || buf[1] != 1 { // only CONNECT supported
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
		ip := net.IP(buf[addrCursor : addrCursor+net.IPv4len])
		if !allowPrivateDest && isPrivateOrLocalIP(ip) {
			clientConn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		targetHost = ip.String()
		addrCursor += net.IPv4len
	case 3: // Domain
		domainLen := int(buf[addrCursor])
		addrCursor++
		if domainLen == 0 || n < addrCursor+domainLen+2 {
			return
		}
		targetHost = string(buf[addrCursor : addrCursor+domainLen])
		addrCursor += domainLen
	case 4: // IPv6
		if n < addrCursor+net.IPv6len+2 {
			return
		}
		ip := net.IP(buf[addrCursor : addrCursor+net.IPv6len])
		if !allowPrivateDest && isPrivateOrLocalIP(ip) {
			clientConn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		targetHost = ip.String()
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

	// Best-effort keepalive on TCP connections
	if tc, ok := clientConn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(2 * time.Minute)
	}
	if tc, ok := targetTCPConn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(2 * time.Minute)
	}

	errChan := make(chan error, 2)
	go func() { _, err := io.Copy(targetTCPConn, clientConn); errChan <- err }()
	go func() { _, err := io.Copy(clientConn, targetTCPConn); errChan <- err }()
	<-errChan
	<-errChan
}

func StartSocksProxyServer(ctx context.Context, instances []*tor.Instance, appCfg *config.AppConfig) {
	bindIP := strings.TrimSpace(appCfg.SocksBindAddr)
	if bindIP == "" {
		bindIP = "0.0.0.0"
	}
	listenAddr := net.JoinHostPort(bindIP, appCfg.CommonSocksPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("SOCKS: Failed to start SOCKS5 proxy server on %s: %v", listenAddr, err)
	}
	log.Printf("SOCKS5 proxy server listening on %s", listenAddr)

	allowedClientNets := buildAllowedClientNets(appCfg.LANClientCIDRs)
	allowPrivateDest := appCfg.AllowPrivateDest

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
				return
			default:
				log.Printf("SOCKS: Failed to accept connection: %v", err)
				continue
			}
		}

		// Access control: allow only loopback and configured LAN CIDRs
		remoteHost, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if ip := net.ParseIP(remoteHost); ip != nil && !ipInNets(ip, allowedClientNets) {
			_ = conn.Close()
			continue
		}

		// Enable keepalive on accepted client connection
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(2 * time.Minute)
		}

		go handleSocksConnection(conn, instances, appCfg, allowPrivateDest)
	}
}
