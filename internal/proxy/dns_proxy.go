package proxy

import (
	"log"
	"net" 
	"strings" 
	"time"

	"github.com/miekg/dns"
	"torgo/internal/config"
	"torgo/internal/lb"
	"torgo/internal/torinstance"
)

func handleDNSQueryDirectToTorDNSPort(w dns.ResponseWriter, r *dns.Msg, instances []*torinstance.Instance, appCfg *config.AppConfig) {
	if len(r.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m)
		return
	}

	backendInstance, err := lb.GetNextHealthyInstance(instances, appCfg) 
	if err != nil {
		log.Printf("DNS (Direct): No healthy backend Tor instance for query %s from %s: %v", r.Question[0].Name, w.RemoteAddr(), err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	dnsClient := new(dns.Client)
	dnsClient.Timeout = 5 * time.Second 
	
	targetDNSAddr := backendInstance.BackendDNSHost
	if !strings.Contains(targetDNSAddr, ":") { 
		targetDNSAddr = net.JoinHostPort(targetDNSAddr, "53")
	}

	response, _, err := dnsClient.Exchange(r, targetDNSAddr) 

	if err != nil {
		log.Printf("DNS (Direct): Failed to query backend Tor DNS %s for %s from %s: %v", targetDNSAddr, r.Question[0].Name, w.RemoteAddr(), err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}
	if response == nil { 
		log.Printf("DNS (Direct): Received nil response from backend Tor DNS %s for %s from %s", targetDNSAddr, r.Question[0].Name, w.RemoteAddr())
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}
	w.WriteMsg(response)
}

// StartDNSProxyServer starts the common DNS proxy server (UDP and TCP).
func StartDNSProxyServer(instances []*torinstance.Instance, appCfg *config.AppConfig) {
	addr := "0.0.0.0:" + appCfg.CommonDNSPort

	dnsHandler := func(w dns.ResponseWriter, r *dns.Msg) {
		handleDNSQueryDirectToTorDNSPort(w, r, instances, appCfg) 
	}
	dns.HandleFunc(".", dnsHandler)


	go func() {
		serverUDP := &dns.Server{Addr: addr, Net: "udp", ReusePort: true}
		log.Printf("DNS proxy (direct to Tor DNSPort) listening on %s (UDP)", addr)
		if err := serverUDP.ListenAndServe(); err != nil {
			if err != nil && err.Error() != "dns: Server closed" && !strings.Contains(err.Error(), "use of closed network connection") { 
				log.Fatalf("Failed to start DNS UDP proxy on %s: %v", addr, err)
			} else if err != nil { 
				log.Printf("DNS UDP proxy server on %s shut down: %v", addr, err)
			} else { 
				log.Printf("DNS UDP proxy server on %s shut down gracefully.", addr)
			}
		}
	}()

	go func() {
		serverTCP := &dns.Server{Addr: addr, Net: "tcp", ReusePort: true}
		log.Printf("DNS proxy (direct to Tor DNSPort) listening on %s (TCP)", addr)
		if err := serverTCP.ListenAndServe(); err != nil {
			if err != nil && err.Error() != "dns: Server closed" && !strings.Contains(err.Error(), "use of closed network connection") {
				log.Fatalf("Failed to start DNS TCP proxy on %s: %v", addr, err)
			} else if err != nil {
				log.Printf("DNS TCP proxy server on %s shut down: %v", addr, err)
			} else {
				log.Printf("DNS TCP proxy server on %s shut down gracefully.", addr)
			}
		}
	}()
}
