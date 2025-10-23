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

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
		return
	}
	_ = c.Close()
}

func setKeepAlive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(2 * time.Minute)
	}
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

	// Greeting: VER, NMETHODS
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	nmethods := int(hdr[1])
	if nmethods == 0 || nmethods > 16 { // small sanity limit
		return
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		return
	}
	clientSupportsNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			clientSupportsNoAuth = true
			break
		}
	}
	if !clientSupportsNoAuth {
		_, _ = clientConn.Write([]byte{0x05, 0xFF})
		return
	}
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	if err := clientConn.SetReadDeadline(time.Now().Add(appCfg.SocksTimeout)); err != nil {
		return
	}
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, reqHdr); err != nil {
		return
	}
	if reqHdr[0] != 0x05 {
		return
	}
	if reqHdr[1] != 0x01 { // only CONNECT
		_, _ = clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	atyp := reqHdr[3]

	var targetHost string
	switch atyp {
	case 0x01: // IPv4
		addr := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(clientConn, addr); err != nil {
			return
		}
		ip := net.IP(addr)
		if !allowPrivateDest && isPrivateOrLocalIP(ip) {
			_, _ = clientConn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		targetHost = ip.String()
	case 0x03: // DOMAIN
		l := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, l); err != nil {
			return
		}
		dlen := int(l[0])
		if dlen == 0 || dlen > 253 {
			return
		}
		domain := make([]byte, dlen)
		if _, err := io.ReadFull(clientConn, domain); err != nil {
			return
		}
		targetHost = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(clientConn, addr); err != nil {
			return
		}
		ip := net.IP(addr)
		if !allowPrivateDest && isPrivateOrLocalIP(ip) {
			_, _ = clientConn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		targetHost = ip.String()
	default:
		_, _ = clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, portBuf); err != nil {
		return
	}
	targetPort := int(portBuf[0])<<8 | int(portBuf[1])
	if targetPort <= 0 || targetPort > 65535 {
		_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	targetAddress := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))

	// clear deadlines for long-lived proxying
	_ = clientConn.SetReadDeadline(time.Time{})

	dialer, err := proxy.SOCKS5("tcp", backendInstance.GetBackendSocksHost(), nil, &net.Dialer{
		Timeout: appCfg.SocksTimeout,
	})
	if err != nil {
		_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	targetTCPConn, err := dialer.Dial("tcp", targetAddress)
	if err != nil {
		replyCode := byte(0x01)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			replyCode = 0x06
		}
		_, _ = clientConn.Write([]byte{0x05, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetTCPConn.Close()

	if _, err := clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Best-effort keepalive on TCP connections
	setKeepAlive(clientConn)
	setKeepAlive(targetTCPConn)

	// Bi-directional relay with half-close to avoid hangs
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(targetTCPConn, clientConn)
		closeWrite(targetTCPConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, targetTCPConn)
		closeWrite(clientConn)
		done <- struct{}{}
	}()
	<-done
	<-done
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
		setKeepAlive(conn)

		go handleSocksConnection(conn, instances, appCfg, allowPrivateDest)
	}
}
