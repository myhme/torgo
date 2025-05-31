package dns

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

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
			w.WriteMsg(cachedMsg)
			return
		}
	}

	backendInstance, err := lb.GetNextHealthyInstance(instances)
	if err != nil {
		log.Printf("DNS Proxy: No healthy Tor instance for %s: %v", question.Name, err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	dnsClient := new(dns.Client)
	dnsClient.Timeout = appCfg.DNSTimeout
	targetDNSAddr := backendInstance.GetBackendDNSHost()
	if !strings.Contains(targetDNSAddr, ":") {
		targetDNSAddr = net.JoinHostPort(targetDNSAddr, "53")
	}

	response, _, err := dnsClient.Exchange(r, targetDNSAddr)
	if err != nil {
		log.Printf("DNS Proxy: Failed query to Tor DNS %s (inst %d) for %s: %v", targetDNSAddr, backendInstance.InstanceID, question.Name, err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}
	if response == nil {
		log.Printf("DNS Proxy: Nil response from Tor DNS %s (inst %d) for %s", targetDNSAddr, backendInstance.InstanceID, question.Name)
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

	go func() {
		log.Printf("DNS proxy server listening on %s (UDP)", addr)
		if err := udpServer.ListenAndServe(); err != nil && !isServerClosedError(err) {
			log.Fatalf("DNS UDP proxy server failed: %v", err)
		}
		log.Printf("DNS UDP proxy server on %s shut down.", addr)
	}()
	go func() {
		log.Printf("DNS proxy server listening on %s (TCP)", addr)
		if err := tcpServer.ListenAndServe(); err != nil && !isServerClosedError(err) {
			log.Fatalf("DNS TCP proxy server failed: %v", err)
		}
		log.Printf("DNS TCP proxy server on %s shut down.", addr)
	}()

	go func() {
		<-ctx.Done()
		log.Println("DNS Proxy: Shutting down DNS servers...")
		udpServer.Shutdown()
		tcpServer.Shutdown()
		cache := GetGlobalDNSCache()
		if cache != nil {
			cache.Stop()
		}
		log.Println("DNS Proxy: DNS servers shut down.")
	}()
}

func isServerClosedError(err error) bool {
	return strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "Server closed")
}
