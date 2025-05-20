package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
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

	appCfg := config.LoadConfig() // Load configuration once

	log.Printf("Initializing 'torgo' for %d backend Tor instance(s). Stagger delay: %v", appCfg.NumTorInstances, appCfg.RotationStaggerDelay)
	log.Printf("Common SOCKS on port: %s, Common DNS on port: %s, Management API on port: %s", appCfg.CommonSocksPort, appCfg.CommonDNSPort, appCfg.APIPort)

	backendInstances := make([]*torinstance.Instance, appCfg.NumTorInstances)
	for i := 0; i < appCfg.NumTorInstances; i++ {
		instanceID := i + 1
		// Pass appCfg to New, so instance methods can access global settings like timeouts
		backendInstances[i] = torinstance.New(instanceID, appCfg) 
	}

	// Create a cancellable context for graceful shutdown
	mainCtx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure cancel is called eventually to clean up resources if main exits early

	// Start health monitoring
	go health.Monitor(mainCtx, backendInstances, appCfg)

	// Start common SOCKS5 proxy server
	go proxy.StartSocksProxyServer(backendInstances, appCfg)

	// Start common DNS proxy server
	go proxy.StartDNSProxyServer(backendInstances, appCfg)

	// Setup HTTP API router
	// The MasterAPIRouter now directly uses the instances and appCfg
	httpMux := http.NewServeMux() // Use a new ServeMux for clarity
	httpMux.HandleFunc("/webui", api.WebUIHandler) // Serve HTML at /webui
	httpMux.HandleFunc("/webui/", api.WebUIHandler) // Also handle if user types /webui/

	// API routes
	httpMux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) { // Catch-all for API
		api.MasterAPIRouter(w, r, backendInstances, appCfg)
	})


	apiServer := &http.Server{
		Addr:    ":" + appCfg.APIPort,
		Handler: httpMux, // Use the new mux
		ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, // Increased for potentially long streaming like staggered rotate
		IdleTimeout: 60 * time.Second,
	}

	go func() {
		log.Printf("Management API server (and WebUI at /webui) listening on :%s", appCfg.APIPort)
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start management API server: %v", err)
		}
	}()

	// Wait for termination signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("Received signal: %s. Shutting down torgo application...", sig)

	// Trigger context cancellation for goroutines like health monitor
	cancel()

	// Shutdown HTTP server gracefully
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second) // Increased shutdown timeout
	defer shutdownCancel()
	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("API server shutdown error: %v", err)
	}

	// Add any other cleanup for Tor instances if necessary (e.g., closing control connections)
	log.Println("Closing Tor instance control connections...")
	for _, instance := range backendInstances {
		instance.Mu.Lock()
		instance.CloseControlConnUnlocked() // Ensure control connections are closed
		instance.Mu.Unlock()
	}

	log.Println("Torgo application shut down gracefully.")
}
