package socks

import (
	"context"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
	"torgo/internal/config"
	"torgo/internal/lb"
	"torgo/internal/tor"
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

// validate domain according to basic RFC rules (ASCII, label length, allowed chars, TLD not all-numeric)
func isValidHostname(h string) bool {
	if h == "" {
		return false
	}
	if strings.HasSuffix(h, ".") {
		h = strings.TrimSuffix(h, ".")
	}
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	h = strings.ToLower(h)
	labels := strings.Split(h, ".")
	for i, lab := range labels {
		if len(lab) == 0 || len(lab) > 63 {
			return false
		}
		if lab[0] == '-' || lab[len(lab)-1] == '-' {
			return false
		}
		alphaInTLD := false
		for j := 0; j < len(lab); j++ {
			c := lab[j]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
				if i == len(labels)-1 && (c >= 'a' && c <= 'z') {
					alphaInTLD = true
				}
				continue
			}
			return false
		}
		if i == len(labels)-1 && !alphaInTLD {
			return false
		}
	}
	return true
}

func handleSocksConnection(clientConn net.Conn, instances []*tor.Instance, appCfg *config.AppConfig, allowPrivateDest bool) {
	defer clientConn.Close()

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
		domain := string(buf[addrCursor : addrCursor+domainLen])
		if !isValidHostname(domain) {
			clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		targetHost = domain
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

	// Select a healthy backend with brief retries to allow Tor to finish bootstrapping
	var backendInstance *tor.Instance
	for i := 0; i < 5; i++ {
		bi, err := lb.GetNextHealthyInstance(instances)
		if err == nil {
			backendInstance = bi
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if backendInstance == nil {
		// No healthy backend available after retries; fail quietly to avoid log spam
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	backendInstance.IncrementActiveConnections()
	defer backendInstance.DecrementActiveConnections()

	dialer, err := proxy.SOCKS5("tcp", backendInstance.GetBackendSocksHost(), nil, &net.Dialer{
		Timeout: appCfg.SocksTimeout,
	})
	if err != nil {
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	targetTCPConn, err := dialer.Dial("tcp", targetAddress)
