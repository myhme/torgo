package proxy

import (
	"log"
	"net" // Required for net.ErrClosed
	"time"

	"github.com/miekg/dns"
	"torgo/internal/config"
	"torgo/internal/lb"
	"torgo/internal/torinstance"
)

func handleDNSQuery(w dns.ResponseWriter, r *dns.Msg, instances []*torinstance.Instance, appCfg *config.AppConfig) {
	if len(r.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m)
		return
	}

	backendInstance, err := lb.GetNextHealthyInstance(instances, appCfg)
	if err != nil {
		log.Printf("DNS: No healthy backend Tor for query %s from %s: %v", r.Question[0].Name, w.RemoteAddr(), err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	dnsClient := new(dns.Client)
	dnsClient.Timeout = 5 * time.Second // Timeout for DNS query to backend Tor instance
	
	response, _, err := dnsClient.Exchange(r, backendInstance.BackendDNSHost)

	if err != nil {
		log.Printf("DNS: Failed to query backend Tor %s for %s from %s: %v", backendInstance.BackendDNSHost, r.Question[0].Name, w.RemoteAddr(), err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}
	if response == nil { 
		log.Printf("DNS: Received nil response from backend Tor %s for %s from %s", backendInstance.BackendDNSHost, r.Question[0].Name, w.RemoteAddr())
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
		handleDNSQuery(w, r, instances, appCfg)
	}
	dns.HandleFunc(".", dnsHandler)


	go func() {
		serverUDP := &dns.Server{Addr: addr, Net: "udp", ReusePort: true}
		log.Printf("DNS proxy server listening on %s (UDP, LB to backend Tor instances)", addr)
		if err := serverUDP.ListenAndServe(); err != nil {
			// For miekg/dns, ListenAndServe returns nil on graceful shutdown via server.Shutdown()
			// If it returns an error, it's usually a problem.
			// net.ErrClosed might be seen if the underlying socket is closed unexpectedly.
			if err != nil && err.Error() != "dns: Server closed" && err != net.ErrClosed { // miekg/dns might return "dns: Server closed"
				log.Fatalf("Failed to start DNS UDP proxy on %s: %v", addr, err)
			} else if err != nil { // Log other closure types as info
				log.Printf("DNS UDP proxy server on %s shut down: %v", addr, err)
			} else { // err is nil, graceful shutdown
				log.Printf("DNS UDP proxy server on %s shut down gracefully.", addr)
			}
		}
	}()

	go func() {
		serverTCP := &dns.Server{Addr: addr, Net: "tcp", ReusePort: true}
		log.Printf("DNS proxy server listening on %s (TCP, LB to backend Tor instances)", addr)
		if err := serverTCP.ListenAndServe(); err != nil {
			if err != nil && err.Error() != "dns: Server closed" && err != net.ErrClosed {
				log.Fatalf("Failed to start DNS TCP proxy on %s: %v", addr, err)
			} else if err != nil {
				log.Printf("DNS TCP proxy server on %s shut down: %v", addr, err)
			} else {
				log.Printf("DNS TCP proxy server on %s shut down gracefully.", addr)
			}
		}
	}()
}
