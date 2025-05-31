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
	log.Println("Starting torgo application...")

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

	mainCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Println("Performing initial health checks for all instances before starting proxy servers...")
	var initialHealthCheckWG sync.WaitGroup
	for _, instance := range backendInstances {
		initialHealthCheckWG.Add(1)
		go func(inst *tor.Instance) {
			defer initialHealthCheckWG.Done()
			inst.CheckHealth(mainCtx)
		}(instance)
	}
	initialHealthCheckWG.Wait()
	log.Println("Initial health checks completed for all instances.")

	// Initialize DNS Cache if enabled
	if appCfg.DNSCacheEnabled {
		dns.SetGlobalDNSCache(dns.NewDNSCache(appCfg)) // NewDNSCache now returns *DNSCache
		log.Println("Global DNS Cache Initialized.")
	}

	// Start core services
	go health.Monitor(mainCtx, backendInstances, appCfg)
	go socks.StartSocksProxyServer(mainCtx, backendInstances, appCfg)
	go dns.StartDNSProxyServer(mainCtx, backendInstances, appCfg)

	// Start IP Diversity Monitor
	if appCfg.MinInstancesForIPDiversityCheck > 0 && appCfg.NumTorInstances >= appCfg.MinInstancesForIPDiversityCheck {
		go rotation.MonitorIPDiversity(mainCtx, backendInstances, appCfg)
	} else {
		log.Println("IP Diversity Monitor: Disabled due to configuration.")
	}

	// Start Automatic Circuit Rotation Monitor
	if appCfg.IsAutoRotationEnabled && appCfg.AutoRotateCircuitInterval > 0 {
		go rotation.MonitorAutoRotation(mainCtx, backendInstances, appCfg)
	} else {
		log.Println("Automatic Circuit Rotation Monitor: Disabled by configuration.")
	}

	// Setup HTTP server for API and WebUI
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

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("Received signal: %s. Shutting down torgo application...", sig)

	cancel() // Signal all background goroutines to stop

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer shutdownCancel()

	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("API server shutdown error: %v", err)
	}

	log.Println("Closing Tor instance control connections...")
	for _, instance := range backendInstances {
		instance.CloseControlConnection()
	}

	// Wait for a moment for goroutines to finish (simple approach)
	time.Sleep(2 * time.Second)

	log.Println("Torgo application shut down gracefully.")
}
