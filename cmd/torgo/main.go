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
	"torgo/internal/autorotate" // New import
	"torgo/internal/config"
	"torgo/internal/health"
	"torgo/internal/ipdiversity"
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
		// Initialize LastCircuitRecreationTime to now for new instances if desired,
		// or let the first NEWNYM (e.g. from health check or manual) set it.
		// For auto-rotation, having it zero means it's eligible sooner.
		// If we want to give them a grace period equal to the interval:
		// if appCfg.IsAutoRotationEnabled {
		//    backendInstances[i].LastCircuitRecreationTime = time.Now()
		// }
	}

	mainCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Println("Performing initial health checks for all instances before starting proxy servers...")
	var initialHealthCheckWG sync.WaitGroup
	for _, instance := range backendInstances {
		initialHealthCheckWG.Add(1)
		go func(inst *torinstance.Instance) {
			defer initialHealthCheckWG.Done()
			inst.CheckHealth(mainCtx) // This might send NEWNYM if instance is stuck, thus setting LastCircuitRecreationTime
		}(instance)
	}
	initialHealthCheckWG.Wait()
	log.Println("Initial health checks completed for all instances.")

	// Start core services
	go health.Monitor(mainCtx, backendInstances, appCfg)
	go proxy.StartSocksProxyServer(backendInstances, appCfg)
	go proxy.StartDNSProxyServer(backendInstances, appCfg)

	// Start IP Diversity Monitor
	if appCfg.MinInstancesForIPDiversityCheck > 0 && appCfg.NumTorInstances >= appCfg.MinInstancesForIPDiversityCheck {
		go ipdiversity.MonitorIPDiversity(mainCtx, backendInstances, appCfg)
	} else {
		log.Println("IP Diversity Monitor: Disabled due to configuration (MinInstancesForIPDiversityCheck or NumTorInstances too low).")
	}

	// Start Automatic Circuit Rotation Monitor
	if appCfg.IsAutoRotationEnabled && appCfg.AutoRotateCircuitInterval > 0 {
		go autorotate.MonitorAutoRotation(mainCtx, backendInstances, appCfg)
	} else {
		log.Println("Automatic Circuit Rotation Monitor: Disabled by configuration.")
	}

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/webui", api.WebUIHandler) // Serve at /webui
	httpMux.HandleFunc("/webui/", api.WebUIHandler) // Also handle if accessed with trailing slash
	httpMux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		api.MasterAPIRouter(w, r, backendInstances, appCfg)
	})

	apiServer := &http.Server{
		Addr:         ":" + appCfg.APIPort,
		Handler:      httpMux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second, // Increased for potentially long streaming like rotate-all
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

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 25*time.Second) // Increased for graceful shutdown
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
