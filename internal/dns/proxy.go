package dns

import (
	"context"
	"log"
	"net"
	"strings"
	// "time" // Unused import removed

	"github.com/miekg/dns"
	"torgo/internal/config"
	"torgo/internal/lb"
	"torgo/internal/tor"
)

// handleDNSQuery routes DNS queries, checking cache first, then to a Tor instance.
func handleDNSQuery(w dns.ResponseWriter, r *dns.Msg, instances []*tor.Instance, appCfg *config.AppConfig) {
	if len(r.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(m)
		return
	}
	question := r.Question[0]

	cache := GetGlobalDNSCache() // Get the global cache instance
	if cache != nil {            // Check if cache object exists (was initialized)
		if cachedMsg, found := cache.Get(question); found {
			// log.Printf("DNS Cache: HIT for %s type %s", question.Name, dns.TypeToString[question.Qtype])
			// Set the ID of the cached response to match the ID of the current query
			cachedMsg.Id = r.Id
			w.WriteMsg(cachedMsg)
			return
		}
		// log.Printf("DNS Cache: MISS for %s type %s", question.Name, dns.TypeToString[question.Qtype])
	}

	// Cache miss or cache disabled/not initialized, proceed to fetch from Tor DNS
	backendInstance, err := lb.GetNextHealthyInstance(instances)
	if err != nil {
		log.Printf("DNS Proxy: No healthy backend Tor instance for query %s from %s: %v", question.Name, w.RemoteAddr(), err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	dnsClient := new(dns.Client)
	dnsClient.Timeout = appCfg.DNSTimeout // Use configured timeout

	// Tor instances listen on their specific DNS ports (e.g., 127.0.0.1:9201)
	targetDNSAddr := backendInstance.GetBackendDNSHost() // Use method to get this
	if !strings.Contains(targetDNSAddr, ":") {          // Ensure port is part of the address
		targetDNSAddr = net.JoinHostPort(targetDNSAddr, "53") // Default DNS port if not specified
	}

	response, _, err := dnsClient.Exchange(r, targetDNSAddr)

	if err != nil {
		log.Printf("DNS Proxy: Failed to query Tor DNS %s (instance %d) for %s: %v", targetDNSAddr, backendInstance.InstanceID, question.Name, err)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}
	if response == nil { // Should not happen if err is nil, but good practice
		log.Printf("DNS Proxy: Received nil response from Tor DNS %s (instance %d) for %s", targetDNSAddr, backendInstance.InstanceID, question.Name)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	// If successful and cache is enabled/initialized, store in cache
	if cache != nil && response.Rcode == dns.RcodeSuccess {
		cache.Set(question, response)
	}

	// The response from dnsClient.Exchange already has the correct ID matching r.Id
	w.WriteMsg(response)
}

// StartDNSProxyServer starts the common DNS proxy server (UDP and TCP).
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
		// It's important to shutdown servers to release ports and stop listeners.
		if err := udpServer.Shutdown(); err != nil {
			log.Printf("DNS Proxy: Error shutting down UDP server: %v", err)
		}
		if err := tcpServer.Shutdown(); err != nil {
			log.Printf("DNS Proxy: Error shutting down TCP server: %v", err)
		}
		cache := GetGlobalDNSCache()
		if cache != nil {
			cache.Stop()
		}
		log.Println("DNS Proxy: DNS servers shut down.")
	}()
}

// isServerClosedError checks if the error is a common "server closed" type error.
func isServerClosedError(err error) bool {
	if err == nil {
		return false
	}
	// Check for common error strings indicating a graceful shutdown or listener close.
	// This list might need adjustment based on OS or Go version specifics.
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "Server closed") ||
		strings.Contains(errStr, "listener closed") // Added for robustness
}
