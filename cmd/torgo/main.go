package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"torgo/internal/api"
	"torgo/internal/config"
	"torgo/internal/dns"
	"torgo/internal/health"
	"torgo/internal/rotation"
	"torgo/internal/socks"
	"torgo/internal/tor"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
	log.Println("Starting torgo application (S6 Managed)...")

	appCfg := config.LoadConfig()

	log.Printf("Initializing 'torgo' for %d backend Tor instance(s). Stagger delay: %v", appCfg.NumTorInstances, appCfg.RotationStaggerDelay)
	log.Printf("Common SOCKS on port: %s, Common DNS on port: %s, Management API on port: %s", appCfg.CommonSocksPort, appCfg.CommonDNSPort, appCfg.APIPort)
	if appCfg.DNSCacheEnabled {
		log.Printf("DNS Cache: ENABLED. Eviction Interval: %v, Default Min TTL: %ds", appCfg.DNSCacheEvictionInterval, appCfg.DNSCacheDefaultMinTTLSeconds)
	} else {
		log.Println("DNS Cache: DISABLED.")
	}

	backendInstances := make([]*tor.Instance, appCfg.NumTorInstances)
	for i := 0; i < appCfg.NumTorInstances; i++ {
		instanceID := i + 1
		backendInstances[i] = tor.New(instanceID, appCfg)
	}

	// S6 Overlay handles service readiness, so initial health checks here might be redundant
	// if S6 services depend on Tor instances being somewhat up (e.g. cookies present).
	// However, torgo-app itself still benefits from knowing their state.
	// The 01-tor-setup script in S6 waits for cookies.
	log.Println("Tor instances assumed to be starting/started by S6. Performing initial health checks...")
	mainCtx, cancel := context.WithCancel(context.Background()) // mainCtx for torgo app lifecycle
	defer cancel()

	var initialHealthCheckWG sync.WaitGroup
	for _, instance := range backendInstances {
		initialHealthCheckWG.Add(1)
		go func(inst *tor.Instance) {
			defer initialHealthCheckWG.Done()
			// Give Tor instances a bit more time to come up if S6 just started them
			time.Sleep(5 * time.Second) // Adjust as needed, or rely on S6 readiness
			inst.CheckHealth(mainCtx)
		}(instance)
	}
	initialHealthCheckWG.Wait()
	log.Println("Initial health checks completed for all instances by torgo-app.")

	// Initialize DNS Cache if enabled
	if appCfg.DNSCacheEnabled {
		dns.SetGlobalDNSCache(dns.NewDNSCache(appCfg))
		log.Println("Global DNS Cache Initialized by torgo-app.")
	}

	// Start core services managed by torgo-app's goroutines
	go health.Monitor(mainCtx, backendInstances, appCfg)
	go socks.StartSocksProxyServer(mainCtx, backendInstances, appCfg)
	go dns.StartDNSProxyServer(mainCtx, backendInstances, appCfg)

	if appCfg.MinInstancesForIPDiversityCheck > 0 && appCfg.NumTorInstances >= appCfg.MinInstancesForIPDiversityCheck {
		go rotation.MonitorIPDiversity(mainCtx, backendInstances, appCfg)
	} else {
		log.Println("IP Diversity Monitor: Disabled by configuration.")
	}

	if appCfg.IsAutoRotationEnabled && appCfg.AutoRotateCircuitInterval > 0 {
		go rotation.MonitorAutoRotation(mainCtx, backendInstances, appCfg)
	} else {
		log.Println("Automatic Circuit Rotation Monitor: Disabled by configuration.")
	}

	httpMux := http.NewServeMux()
	api.RegisterWebUIHandlers(httpMux)
	api.RegisterAPIHandlers(httpMux, backendInstances, appCfg)

	apiServer := &http.Server{
		Addr:         ":" + appCfg.APIPort,
		Handler:      httpMux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("Management API server (and WebUI at /webui) listening on :%s", appCfg.APIPort)
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start management API server: %v", err)
		}
	}()

	// Graceful shutdown handling for torgo-app itself
	// S6 will send SIGTERM to this process (PID 1 in its service definition)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM) // SIGTERM is what S6 sends by default
	sig := <-quit
	log.Printf("Received signal: %s. Shutting down torgo application...", sig)

	cancel() // Signal all torgo-app's background goroutines to stop

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer shutdownCancel()

	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("API server shutdown error: %v", err)
	}

	log.Println("Closing Tor instance control connections from torgo-app...")
	for _, instance := range backendInstances {
		instance.CloseControlConnection()
	}

	time.Sleep(2 * time.Second) // Allow goroutines to finish
	log.Println("Torgo application shut down gracefully.")
	// S6 will handle stopping the Tor and Privoxy services.
}
