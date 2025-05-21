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
	// "math/rand" // For seeding if needed, but time.Now().UnixNano() is often sufficient for non-crypto rand

	"torgo/internal/api"
	"torgo/internal/circuitmanager" // Updated
	"torgo/internal/config"
	"torgo/internal/health"
	// "torgo/internal/ipdiversity" // Replaced by circuitmanager
	// "torgo/internal/autorotate" // Replaced by circuitmanager
	"torgo/internal/proxy"
	"torgo/internal/torinstance"
)

func main() {
	// Seed random number generator (for load balancer, if random strategy is used)
	// rand.Seed(time.Now().UnixNano()) // Go 1.20+ seeds globally automatically. Explicit seed is fine for older versions or clarity.

	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
	log.Println("Starting torgo application...")

	appCfg := config.LoadConfig()

	log.Printf("Initializing 'torgo' for %d backend Tor instance(s).", appCfg.NumTorInstances)
	log.Printf("Common SOCKS on port: %s, Common DNS on port: %s, Management API on port: %s", appCfg.CommonSocksPort, appCfg.CommonDNSPort, appCfg.APIPort)

	backendInstances := make([]*torinstance.Instance, appCfg.NumTorInstances)
	for i := 0; i < appCfg.NumTorInstances; i++ {
		instanceID := i + 1
		backendInstances[i] = torinstance.New(instanceID, appCfg)
	}

	mainCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Println("Performing initial health checks for all instances before starting proxy servers...")
	var initialHealthCheckWG sync.WaitGroup
	for _, instance := range backendInstances {
		initialHealthCheckWG.Add(1)
		go func(inst *torinstance.Instance) {
			defer initialHealthCheckWG.Done()
			inst.CheckHealth(mainCtx)
		}(instance)
	}
	initialHealthCheckWG.Wait()
	log.Println("Initial health checks completed for all instances.")

	// Start core services
	go health.Monitor(mainCtx, backendInstances, appCfg) // Health monitor remains separate
	go proxy.StartSocksProxyServer(backendInstances, appCfg)
	go proxy.StartDNSProxyServer(backendInstances, appCfg)

	// Start the new CircuitManager
	cm := circuitmanager.New(mainCtx, appCfg, backendInstances)
	cm.Start() // This will internally decide if its components run based on config

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
		WriteTimeout: 45 * time.Second, // Increased for potentially long streaming like rotate-all or getting many stats
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

	cm.Stop() // Stop the circuit manager gracefully
	cancel()   // Signal all other background goroutines via mainCtx

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second) // Increased for graceful shutdown
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
