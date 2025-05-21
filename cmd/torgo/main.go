package main

import (
	"context"
	"log/slog" // Import slog
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"torgo/internal/api"
	"torgo/internal/circuitmanager"
	"torgo/internal/config"
	"torgo/internal/health"
	"torgo/internal/proxy"
	"torgo/internal/torinstance"
)

func main() {
	// Load configuration first, as it contains logging settings
	appCfg := config.LoadConfig()

	// Setup structured logger (slog)
	var logHandler slog.Handler
	opts := &slog.HandlerOptions{
		Level:     appCfg.LogLevel,
		AddSource: true, // Include source file and line number
	}
	if appCfg.LogFormat == "json" {
		logHandler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		logHandler = slog.NewTextHandler(os.Stdout, opts)
	}
	logger := slog.New(logHandler)
	slog.SetDefault(logger) // Set as the default logger for the application

	slog.Info("Starting torgo application...", "version", "v3.slog_exported_handlers") 

	slog.Info("Configuration Details",
		slog.Int("tor_instances", appCfg.NumTorInstances),
		slog.String("common_socks_port", appCfg.CommonSocksPort),
		slog.String("common_dns_port", appCfg.CommonDNSPort),
		slog.String("api_port", appCfg.APIPort),
		slog.String("load_balancing_strategy", appCfg.LoadBalancingStrategy),
	)

	backendInstances := make([]*torinstance.Instance, appCfg.NumTorInstances)
	for i := 0; i < appCfg.NumTorInstances; i++ {
		instanceID := i + 1
		backendInstances[i] = torinstance.New(instanceID, appCfg)
	}

	mainCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	slog.Info("Performing initial health checks for all instances...")
	var initialHealthCheckWG sync.WaitGroup
	for _, instance := range backendInstances {
		initialHealthCheckWG.Add(1)
		go func(inst *torinstance.Instance) {
			defer initialHealthCheckWG.Done()
			inst.CheckHealth(mainCtx)
		}(instance)
	}
	initialHealthCheckWG.Wait()
	slog.Info("Initial health checks completed.")

	// Start core services
	go health.Monitor(mainCtx, backendInstances, appCfg)
	go proxy.StartSocksProxyServer(backendInstances, appCfg)
	go proxy.StartDNSProxyServer(backendInstances, appCfg)

	cm := circuitmanager.New(mainCtx, appCfg, backendInstances)
	cm.Start()

	// Setup API router using Go 1.22+ features
	httpMux := http.NewServeMux()

	// Static/simple routes
	httpMux.HandleFunc("/webui", api.WebUIHandler) 
	httpMux.HandleFunc("/webui/", api.WebUIHandler) 
	
	httpMux.HandleFunc("GET /api/v1/app-details", api.AppDetailsHandler(appCfg))
	// Ensure these handler names match the EXPORTED (capitalized) names in api/handlers.go
	httpMux.HandleFunc("GET /api/v1/rotate-all-staggered", api.RotateAllStaggeredHandler(backendInstances, appCfg))
	httpMux.HandleFunc("POST /api/v1/rotate-all-staggered", api.RotateAllStaggeredHandler(backendInstances, appCfg))

	// Per-instance routes using path parameters {instanceid}
	httpMux.HandleFunc("GET /api/v1/instance/{instanceid}/rotate", api.InstanceActionHandler(backendInstances, appCfg, api.HandleRotate))
	httpMux.HandleFunc("POST /api/v1/instance/{instanceid}/rotate", api.InstanceActionHandler(backendInstances, appCfg, api.HandleRotate))
	httpMux.HandleFunc("GET /api/v1/instance/{instanceid}/health", api.InstanceActionHandler(backendInstances, appCfg, api.HandleHealth))
	httpMux.HandleFunc("GET /api/v1/instance/{instanceid}/stats", api.InstanceActionHandler(backendInstances, appCfg, api.HandleStats))
	httpMux.HandleFunc("GET /api/v1/instance/{instanceid}/ip", api.InstanceActionHandler(backendInstances, appCfg, api.HandleIP))
	httpMux.HandleFunc("GET /api/v1/instance/{instanceid}/config", api.InstanceActionHandler(backendInstances, appCfg, api.HandleGetInstanceConfig))
	httpMux.HandleFunc("POST /api/v1/instance/{instanceid}/config/{porttype}", api.InstanceActionHandler(backendInstances, appCfg, api.HandleSetInstancePortConfig)) 
	httpMux.HandleFunc("POST /api/v1/instance/{instanceid}/config/nodepolicy", api.InstanceActionHandler(backendInstances, appCfg, api.HandleSetNodePolicy))
	httpMux.HandleFunc("GET /api/v1/instance/{instanceid}/performancemetrics", api.InstanceActionHandler(backendInstances, appCfg, api.HandleGetPerformanceMetrics))


	apiServer := &http.Server{
		Addr:         ":" + appCfg.APIPort,
		Handler:      httpMux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 45 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("Management API server starting", "address", apiServer.Addr, "webui_path", "/webui")
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Failed to start management API server", slog.Any("error", err))
			os.Exit(1) // Critical failure
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	slog.Info("Received signal, shutting down torgo application...", slog.String("signal", sig.String()))

	cm.Stop()
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("API server shutdown error", slog.Any("error", err))
	}

	slog.Info("Closing Tor instance control connections...")
	for _, instance := range backendInstances {
		instance.Mu.Lock()
		instance.CloseControlConnUnlocked()
		instance.Mu.Unlock()
	}

	slog.Info("Torgo application shut down gracefully.")
}
