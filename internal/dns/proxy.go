package dns

import (
	"context"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
	"torgo/internal/config"
	"torgo/internal/lb"
	"torgo/internal/tor"
)

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
		log.Printf("DNS Proxy: No healthy backend Tor instance for query %s: %v", question.Name, err)
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
		log.Printf("DNS Proxy: Failed to query Tor DNS %s (instance %d) for %s: %v", targetDNSAddr, backendInstance.InstanceID, question.Name, err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	if cache != nil && response.Rcode == dns.RcodeSuccess {
		cache.Set(question, response)
	}

	w.WriteMsg(response)
}

func StartDNSProxyServer(ctx context.Context, instances []*tor.Instance, appCfg *config.AppConfig) {
	addr := "0.0.0.0:" + appCfg.CommonDNSPort
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
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