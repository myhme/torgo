package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"torgo/internal/api"
	"torgo/internal/config"
	"torgo/internal/dns"
	"torgo/internal/health"
	"torgo/internal/rotation"
	"torgo/internal/secmem"
	"torgo/internal/socks"
	"torgo/internal/tor"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
	log.Println("Starting torgo application...")

	// Best-effort hardening before anything sensitive loads
	secmem.DisableCoreDumpsAndPtrace()
	if err := secmem.Init(); err != nil {
		log.Fatalf("Failed to initialize secure memory: %v", err)
	}
	lockErr := secmem.LockProcessMemoryBestEffort()
	requireMlock := strings.EqualFold(os.Getenv("SECMEM_REQUIRE_MLOCK"), "1") || strings.EqualFold(os.Getenv("SECMEM_REQUIRE_MLOCK"), "true")
	if lockErr != nil {
		if requireMlock {
			log.Fatalf("mlockall required but failed: %v", lockErr)
		}
		log.Printf("Warning: mlockall failed (continuing): %v", lockErr)
	}

	appCfg := config.LoadConfig()

	log.Printf("Initializing 'torgo' for %d backend Tor instance(s).", appCfg.NumTorInstances)
	log.Printf("Common SOCKS on port: %s, Common DNS on port: %s, Management API on port: %s", appCfg.CommonSocksPort, appCfg.CommonDNSPort, appCfg.APIPort)
	if appCfg.DNSCacheEnabled {
		log.Printf("DNS Cache: ENABLED. Eviction Interval: %v", appCfg.DNSCacheEvictionInterval)
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

	log.Println("Performing initial health checks...")
	var initialHealthCheckWG sync.WaitGroup
	for _, instance := range backendInstances {
		initialHealthCheckWG.Add(1)
		go func(inst *tor.Instance) {
			defer initialHealthCheckWG.Done()
			time.Sleep(5 * time.Second) // Give Tor instances time to start
			inst.CheckHealth(mainCtx)
		}(instance)
	}
	initialHealthCheckWG.Wait()
	log.Println("Initial health checks completed.")

	if appCfg.DNSCacheEnabled {
		dns.SetGlobalDNSCache(dns.NewDNSCache(appCfg))
	}

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

	if appCfg.APIAccessEnabled {
		httpMux := http.NewServeMux()
		api.RegisterWebUIHandlers(httpMux)
		api.RegisterAPIHandlers(httpMux, backendInstances, appCfg)

		apiAddr := net.JoinHostPort(appCfg.APIBindAddr, appCfg.APIPort)
		apiServer := &http.Server{
			Addr:              apiAddr,
			Handler:           httpMux,
			ReadTimeout:       15 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		}

		go func() {
			log.Printf("Management API server (and WebUI at /webui) listening on %s", apiAddr)
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start management API server: %v", err)
			}
		}()

		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		sig := <-quit
		log.Printf("Received signal: %s. Shutting down...", sig)

		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer shutdownCancel()

		if err := apiServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("API server shutdown error: %v", err)
		}
	} else {
		log.Println("API/WebUI disabled by configuration (API_ACCESS_ENABLE=false).")
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		sig := <-quit
		log.Printf("Received signal: %s. Shutting down...", sig)

		cancel()
	}

	log.Println("Closing Tor instance control connections...")
	for _, instance := range backendInstances {
		instance.CloseControlConnection()
	}

	secmem.Wipe()

	log.Println("Torgo application shut down gracefully.")
}
