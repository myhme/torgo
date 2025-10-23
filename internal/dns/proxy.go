package dns

import (
	"context"
	"log"
	"net"
	"strings"

	"torgo/internal/config"
	"torgo/internal/lb"
	"torgo/internal/tor"

	"github.com/miekg/dns"
)

// helpers duplicated locally to avoid cross-package deps
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

func filterPrivateIPsInAnswers(msg *dns.Msg, allowPrivate bool) {
	if allowPrivate || msg == nil {
		return
	}
	filtered := make([]dns.RR, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		switch a := rr.(type) {
		case *dns.A:
			if !isPrivateOrLocalIP(a.A) {
				filtered = append(filtered, rr)
			}
		case *dns.AAAA:
			if !isPrivateOrLocalIP(a.AAAA) {
				filtered = append(filtered, rr)
			}
		default:
			filtered = append(filtered, rr)
		}
	}
	msg.Answer = filtered
}

func handleDNSQuery(w dns.ResponseWriter, r *dns.Msg, instances []*tor.Instance, appCfg *config.AppConfig) {
	if len(r.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m)
		return
	}
	question := r.Question[0]

	cache := GetGlobalDNSCache()
	if cache != nil {
		if cachedMsg, found := cache.Get(question); found {
			cachedMsg.Id = r.Id
			w.WriteMsg(cachedMsg)
			return
		}
	}

	backendInstance, err := lb.GetNextHealthyInstance(instances)
	if err != nil {
		log.Printf("DNS Proxy: No healthy backend Tor instance: %v", err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	dnsClient := new(dns.Client)
	dnsClient.Timeout = appCfg.DNSTimeout
	targetDNSAddr := backendInstance.GetBackendDNSHost()

	response, _, err := dnsClient.Exchange(r, targetDNSAddr)
	if err != nil {
		log.Printf("DNS Proxy: Query via %s (inst %d) failed for %s: %v", targetDNSAddr, backendInstance.InstanceID, question.Name, err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	filterPrivateIPsInAnswers(response, appCfg.AllowPrivateDest)

	if cache != nil && response.Rcode == dns.RcodeSuccess {
		cache.Set(question, response)
	}

	w.WriteMsg(response)
}

func StartDNSProxyServer(ctx context.Context, instances []*tor.Instance, appCfg *config.AppConfig) {
	addr := net.JoinHostPort(strings.TrimSpace(appCfg.DNSBindAddr), appCfg.CommonDNSPort)
	allowed := buildAllowedClientNets(appCfg.LANClientCIDRs)

	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		remote := w.RemoteAddr()
		if remote != nil {
			ipStr, _, _ := net.SplitHostPort(remote.String())
			if ip := net.ParseIP(ipStr); ip != nil && !ipInNets(ip, allowed) {
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				w.WriteMsg(m)
				return
			}
		}
		handleDNSQuery(w, r, instances, appCfg)
	})

	udpServer := &dns.Server{Addr: addr, Net: "udp", Handler: dns.DefaultServeMux, ReusePort: true}
	tcpServer := &dns.Server{Addr: addr, Net: "tcp", Handler: dns.DefaultServeMux, ReusePort: true}

	start := func(s *dns.Server, netType string) {
		log.Printf("DNS proxy server listening on %s (%s)", addr, netType)
		if err := s.ListenAndServe(); err != nil && !isServerClosedError(err) {
			log.Fatalf("DNS %s proxy server failed: %v", netType, err)
		}
		log.Printf("DNS %s proxy server on %s shut down.", netType, addr)
	}

	go start(udpServer, "UDP")
	go start(tcpServer, "TCP")

	go func() {
		<-ctx.Done()
		log.Println("DNS Proxy: Shutting down DNS servers...")
		udpServer.Shutdown()
		tcpServer.Shutdown()
		if cache := GetGlobalDNSCache(); cache != nil {
			cache.Stop()
		}
		log.Println("DNS Proxy: DNS servers shut down complete.")
	}()
}

func isServerClosedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "Server closed") ||
		strings.Contains(errStr, "listener closed")
}
