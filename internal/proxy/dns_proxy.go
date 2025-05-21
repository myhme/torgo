package proxy

import (
	"log/slog" // Import slog
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

	qName := r.Question[0].Name
	clientAddr := w.RemoteAddr().String()

	backendInstance, err := lb.GetNextHealthyInstance(instances, appCfg) 
	if err != nil {
		slog.Warn("DNS (Direct): No healthy backend Tor instance for query.", "query_name", qName, "client_addr", clientAddr, slog.Any("error", err))
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	slog.Debug("DNS (Direct): Forwarding query to backend Tor DNS.", 
		"query_name", qName, 
		"client_addr", clientAddr, 
		"backend_instance_id", backendInstance.InstanceID,
		"backend_dns_host", backendInstance.BackendDNSHost,
	)

	dnsClient := new(dns.Client)
	dnsClient.Timeout = 5 * time.Second 
	
	targetDNSAddr := backendInstance.BackendDNSHost
	if !strings.Contains(targetDNSAddr, ":") { 
		targetDNSAddr = net.JoinHostPort(targetDNSAddr, "53")
	}

	response, _, err := dnsClient.Exchange(r, targetDNSAddr) 

	if err != nil {
		slog.Error("DNS (Direct): Failed to query backend Tor DNS.", 
			"target_dns_addr", targetDNSAddr, 
			"query_name", qName, 
			"client_addr", clientAddr, 
			slog.Any("error", err))
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}
	if response == nil { 
		slog.Error("DNS (Direct): Received nil response from backend Tor DNS.", 
			"target_dns_addr", targetDNSAddr, 
			"query_name", qName, 
			"client_addr", clientAddr)
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

	startServer := func(netType string) {
		server := &dns.Server{Addr: addr, Net: netType, ReusePort: true}
		slog.Info("DNS proxy (direct to Tor DNSPort) listening.", "protocol", netType, "address", addr)
		err := server.ListenAndServe()
		if err != nil {
			// "dns: Server closed" and "use of closed network connection" are expected on shutdown.
			if err.Error() != "dns: Server closed" && !strings.Contains(err.Error(), "use of closed network connection") {
				slog.Error("Failed to start DNS proxy server.", "protocol", netType, "address", addr, slog.Any("error", err))
				// Consider if this should be fatal for the whole app. For now, just log.
				// os.Exit(1) // If DNS proxy is critical
			} else {
				slog.Info("DNS proxy server shut down.", "protocol", netType, "address", addr, slog.Any("error", err))
			}
		}
	}

	go startServer("udp")
	go startServer("tcp")
}
