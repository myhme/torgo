package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync" // Added for WaitGroup
	"syscall"
	"time"

	"torgo/internal/api"
	"torgo/internal/config"
	"torgo/internal/health"
	"torgo/internal/proxy"
	"torgo/internal/torinstance"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
	log.Println("Starting torgo application...")

	appCfg := config.LoadConfig()

	log.Printf("Initializing 'torgo' for %d backend Tor instance(s). Stagger delay: %v", appCfg.NumTorInstances, appCfg.RotationStaggerDelay)
	log.Printf("Common SOCKS on port: %s, Common DNS on port: %s, Management API on port: %s", appCfg.CommonSocksPort, appCfg.CommonDNSPort, appCfg.APIPort)

	backendInstances := make([]*torinstance.Instance, appCfg.NumTorInstances)
	for i := 0; i < appCfg.NumTorInstances; i++ {
		instanceID := i + 1
		backendInstances[i] = torinstance.New(instanceID, appCfg)
	}

	mainCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Perform initial health checks synchronously before starting proxies
	log.Println("Performing initial health checks for all instances before starting proxy servers...")
	var initialHealthCheckWG sync.WaitGroup
	for _, instance := range backendInstances {
		initialHealthCheckWG.Add(1)
		go func(inst *torinstance.Instance) {
			defer initialHealthCheckWG.Done()
			// Use a separate context for initial checks that can be shorter if needed,
			// or mainCtx if they should also be cancellable by shutdown signal.
			// For simplicity, using mainCtx here.
			inst.CheckHealth(mainCtx)
		}(instance)
	}
	initialHealthCheckWG.Wait()
	log.Println("Initial health checks completed for all instances.")

	// Start periodic health monitoring (will also run its own first check, which is fine)
	go health.Monitor(mainCtx, backendInstances, appCfg)

	// Start common SOCKS5 proxy server
	go proxy.StartSocksProxyServer(backendInstances, appCfg)

	// Start common DNS proxy server
	go proxy.StartDNSProxyServer(backendInstances, appCfg)

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/webui", api.WebUIHandler)
	httpMux.HandleFunc("/webui/", api.WebUIHandler)
	httpMux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		api.MasterAPIRouter(w, r, backendInstances, appCfg)
	})

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

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("API server shutdown error: %v", err)
	}

	log.Println("Closing Tor instance control connections...")
	for _, instance := range backendInstances {
		instance.Mu.Lock()
		instance.CloseControlConnUnlocked()
		instance.Mu.Unlock()
	}

	log.Println("Torgo application shut down gracefully.")
}
