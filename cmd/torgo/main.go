package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand" // Alias for math/rand
	"net"
	"io"
	"net/http"
	_ "net/http/pprof" // For profiling, if needed
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/mux" // Using Gorilla Mux for routing

	// Import internal packages based on the module name 'torgo'
	"torgo/internal/adblock"
	"torgo/internal/api"
	"torgo/internal/tor"
)

const ifconfig string = "https://ipinfo.io"
const adblockHostsFilePathDefault = "/data/config/dnsmasq/adblock.hosts"

// Global variables
var (
	// Torgo's Tor instance management flags
	torExecutablePath     = flag.String("tor", "/usr/bin/tor", "Path of system's tor binary file")
	initialTorCircuits    = flag.Int("circuit", 5, "Initial and target total of torgo's Tor circuits")
	circuitRenewInterval  = flag.Int("lifeSpan", 300, "Base duration in seconds for torgo's Tor circuit renewal (MaxCircuitDirtiness), will be staggered")
	torExitNodes          = flag.String("exitNode", "", "Specific country codes for torgo's Tor exit circuits (e.g., {us},{ca})")
	torgoInstanceBasePath = flag.String("torgoInstanceBasePath", "/data/config/torgo_instances", "Base directory for torgo's own Tor instance data and torrc files.")
	baseTorrcFile         = flag.String("torrc", "/data/config/torgo_base/base_torrc", "Path to a base torrc file to be merged for torgo's Tor instances. Can be empty.")

	// Network and API flags for torgo app
	listenHost           = flag.String("host", "0.0.0.0", "Hostname or IP address for SOCKS5 LB and API to listen on")
	apiPort              = flag.String("apiPort", "2525", "Port for the torgo REST API and WebUI")
	socksLBPort          = flag.String("lbPort", "9049", "Port for the torgo SOCKS5 load balancer")
	loadBalancerAlgo      = flag.String("lbAlgo", "random", "Load balancing algorithm: rr (round robin), lc (least connection), random")
	
	// Health check for torgo's circuits
	circuitHealthCheckInterval = flag.Duration("healthCheckInterval", 30*time.Minute, "Interval for torgo's Tor circuit health checks")

	// Adblock related flags for torgo app
	initialAdblockURLsFlag  = flag.String("adblockUrls", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "Comma-separated initial URLs for adblock lists")
	adblockUpdateIntervalFlag = flag.Duration("adblockInterval", 24*time.Hour, "Interval for updating adblock lists by torgo app")
	adblockManagedHostsFile = flag.String("adblockHostsFile", adblockHostsFilePathDefault, "Path where torgo writes the merged adblock hosts file for dnsmasq.")

	// Internal state
	currentPortUsage = atomic.Int32{} 
	originalIPInfo tor.IpinfoIo 
	accessKeyFlag  = flag.String("key", "", "API access key; if empty, a key will be generated")
	apiAccessKey   = "" 

	torListGlobal      []tor.TorStruct 
	torListGlobalMutex sync.RWMutex
	mathRandGlobal     *mrand.Rand   
	mathRandMutex      sync.Mutex    
	
	currentAdblockURLs         []string
	currentAdblockURLsMutex    sync.RWMutex
	currentAdblockInterval     time.Duration
	lastAdblockSuccessfulUpdateTime time.Time
	adblockUpdateInProgressMutex  sync.Mutex 
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
	mathRandGlobal = mrand.New(mrand.NewSource(time.Now().UnixNano()))
	currentPortUsage.Store(9090) 
}


func main() {
	flag.Parse()
	currentAdblockInterval = *adblockUpdateIntervalFlag

	if *initialAdblockURLsFlag != "" {
		for _, urlStr := range strings.Split(*initialAdblockURLsFlag, ",") {
			trimmedURL := strings.TrimSpace(urlStr)
			if trimmedURL != "" {
				currentAdblockURLs = append(currentAdblockURLs, trimmedURL)
			}
		}
	}
	log.Printf("INFO: Initial adblock URLs: %v", currentAdblockURLs)
	log.Printf("INFO: Adblock update interval: %s", currentAdblockInterval.String())
	log.Printf("INFO: Adblock hosts file will be managed at: %s", *adblockManagedHostsFile)
	log.Printf("INFO: Base path for torgo's Tor instances: %s", *torgoInstanceBasePath)
	if *baseTorrcFile != "" {
		log.Printf("INFO: Using base torrc for torgo's instances: %s", *baseTorrcFile)
	}

	if *accessKeyFlag == "" {
		const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789=-_"
		const keyLength = 36
		secretBytes := make([]byte, keyLength)
		for i := range secretBytes {
			num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letterBytes))))
			if err != nil { log.Fatalf("FATAL: Keygen: %v", err) }
			secretBytes[i] = letterBytes[num.Int64()]
		}
		apiAccessKey = string(secretBytes)
	} else { apiAccessKey = *accessKeyFlag }
	log.Printf("INFO: API Access key: %s (Header 'access_key')", apiAccessKey)

	ctxInitCurl, cancelInitCurl := context.WithTimeout(context.Background(), 15*time.Second); defer cancelInitCurl()
	bodyNorm, _, err := tor.CurlWithContext(ctxInitCurl, &http.Client{Timeout: 10 * time.Second}, ifconfig)
	if err != nil { log.Fatalf("FATAL: Initial IP: %v", err) }; if err := json.Unmarshal(bodyNorm, &originalIPInfo); err != nil { log.Fatalf("FATAL: Unmarshal IP: %v", err) }
	log.Printf("INFO: Original IP: %s, Country: %s", originalIPInfo.IP, originalIPInfo.Country)

	appCtx, appCancel := context.WithCancel(context.Background()); defer appCancel()
	
	initialCircuits, err := tor.InitTor(appCtx, *initialTorCircuits, *listenHost, *torExecutablePath, *baseTorrcFile, *torgoInstanceBasePath, *torExitNodes, *circuitRenewInterval, originalIPInfo, &currentPortUsage, mathRandGlobal, &mathRandMutex)
	if err != nil { log.Fatalf("FATAL: Init Tor: %v", err) }; torListGlobalMutex.Lock(); torListGlobal = initialCircuits; torListGlobalMutex.Unlock()
	log.Printf("INFO: Initialized %d Tor circuits. PortUsage: %d.", len(initialCircuits), currentPortUsage.Load())

	time.AfterFunc(15*time.Second, func() { 
		_, _, errAdblock := adblock.UpdateAdblockListsAndReloadDnsmasq(appCtx, currentAdblockURLs, *adblockManagedHostsFile, &adblockUpdateInProgressMutex) 
		if errAdblock != nil {
			log.Printf("ERROR: [main] Initial adblock update failed: %v", errAdblock)
		}
		lastAdblockSuccessfulUpdateTime = time.Now()
	})

	go func() { 
		if currentAdblockInterval <= 0 { log.Println("INFO: Periodic adblock updates disabled."); return }
		firstDelay := currentAdblockInterval
		if firstDelay < 15*time.Second { firstDelay = 15*time.Second } 
		time.Sleep(firstDelay) 
		
		ticker := time.NewTicker(currentAdblockInterval); defer ticker.Stop()
		for {
			select {
			case <-appCtx.Done(): log.Println("INFO: Adblock goroutine down."); return
			case <-ticker.C: 
				_, _, errAdblock := adblock.UpdateAdblockListsAndReloadDnsmasq(appCtx, currentAdblockURLs, *adblockManagedHostsFile, &adblockUpdateInProgressMutex)
				if errAdblock != nil {
					log.Printf("ERROR: [main] Periodic adblock update failed: %v", errAdblock)
				}
				lastAdblockSuccessfulUpdateTime = time.Now()
			}
		}
	}()

	// --- Initialize API Handlers with dependencies ---
	apiHandlers := api.NewAPIHandlers(
		&torListGlobal, &torListGlobalMutex, listenHost, socksLBPort,
		torExecutablePath, baseTorrcFile, torgoInstanceBasePath, torExitNodes, circuitRenewInterval,
		&originalIPInfo, &currentPortUsage, mathRandGlobal, &mathRandMutex, appCtx,
		&apiAccessKey,
		&currentAdblockURLs, &currentAdblockURLsMutex, &currentAdblockInterval,
		&lastAdblockSuccessfulUpdateTime, &adblockUpdateInProgressMutex, adblockManagedHostsFile,
	)

	router := mux.NewRouter()
	
	webuiDir := "./static/" 
	if _, err_stat := os.Stat("/app/static/webui.html"); err_stat == nil { 
		webuiDir = "/app/static/"
	}
	
	// Public routes
	router.HandleFunc("/webui", apiHandlers.ServeWebUI(webuiDir)).Methods(http.MethodGet)
	router.PathPrefix("/webui/").Handler(apiHandlers.ServeStatic(webuiDir)) 
	router.HandleFunc("/api/circuits", apiHandlers.GetCircuitsAPIHandler).Methods(http.MethodGet)
	router.HandleFunc("/", apiHandlers.RootAPIHandler) 
	
	apiPublicSubrouter := router.PathPrefix("/api").Subrouter()
	apiPublicSubrouter.HandleFunc("/adblock/config", apiHandlers.GetAdblockConfigAPIHandler).Methods(http.MethodGet)

	// Authenticated API routes
	authedApiSubrouter := router.PathPrefix("/api").Subrouter() 
	authedApiSubrouter.Use(apiHandlers.AuthMiddleware) 

	authedApiSubrouter.HandleFunc("/add/{new:[0-9]+}", apiHandlers.AddCircuitsAPIHandler).Methods(http.MethodPost)
	
	deleteSubrouter := authedApiSubrouter.PathPrefix("/delete").Subrouter()
	deleteSubrouter.HandleFunc("/port/{port}", apiHandlers.DeleteCircuitsByPortAPIHandler).Methods(http.MethodPost)

	authedApiSubrouter.HandleFunc("/adblock/update", apiHandlers.TriggerAdblockUpdateAPIHandler).Methods(http.MethodPost)
	authedApiSubrouter.HandleFunc("/adblock/urls", apiHandlers.AddAdblockURLAPIHandler).Methods(http.MethodPost)
	authedApiSubrouter.HandleFunc("/adblock/url", apiHandlers.DeleteAdblockURLAPIHandler).Methods(http.MethodDelete)


	go func() { 
		listener, errLB := net.Listen("tcp", fmt.Sprintf("%s:%s", *listenHost, *socksLBPort)); if errLB != nil { log.Fatalf("FATAL: SOCKS LB Listen: %v", errLB) }; defer listener.Close(); log.Printf("INFO: SOCKS5 LB listening on %s:%s", *listenHost, *socksLBPort)
		for { conn, errAccept := listener.Accept(); if errAccept != nil { log.Printf("ERROR: SOCKS LB Accept: %v", errAccept); continue }; go handleSocksConnection(conn) }
	}()
	go func() { 
		ticker := time.NewTicker(*circuitHealthCheckInterval); defer ticker.Stop()
		for { select { case <-appCtx.Done(): log.Println("INFO: HealthCheck goroutine down."); return
			case <-ticker.C:
				log.Printf("INFO: HealthCheck: Starting (interval: %s)", circuitHealthCheckInterval.String())
				torListGlobalMutex.RLock(); target := *initialTorCircuits; current := len(torListGlobal); snap := make([]tor.TorStruct, current); copy(snap, torListGlobal); torListGlobalMutex.RUnlock()
				if current == 0 && target > 0 {
					log.Printf("INFO: HealthCheck: No circuits. Initializing to %d.", target); torListGlobalMutex.Lock()
					var initErr error; 
					torListGlobal, initErr = tor.InitTor(appCtx, target, *listenHost, *torExecutablePath, *baseTorrcFile, *torgoInstanceBasePath, *torExitNodes, *circuitRenewInterval, originalIPInfo, &currentPortUsage, mathRandGlobal, &mathRandMutex)
					if initErr != nil { log.Printf("ERROR: HealthCheck: Re-init failed: %v", initErr) } else { log.Printf("INFO: HealthCheck: Re-initialized %d circuits.", len(torListGlobal)) }
					torListGlobalMutex.Unlock(); continue
				}
				if len(snap) == 0 { log.Printf("INFO: HealthCheck: No circuits to check."); continue }
				
				ctxChk, cancelChk := context.WithTimeout(appCtx, 2*time.Minute); 
				statuses := tor.HealthCheck(ctxChk, snap, *listenHost); 
				cancelChk()

				delPorts := make(map[string]bool); updateStatus := make(map[string]tor.HealthStatus) 
				for _, s := range statuses { updateStatus[s.OriginalPort] = s; if !s.IsHealthy { delPorts[s.OriginalPort] = true } }
				
				if len(delPorts) > 0 || len(updateStatus) > 0 {
					torListGlobalMutex.Lock(); newList := make([]tor.TorStruct, 0, len(torListGlobal)); deleted := 0
					for i_loop := range torListGlobal { // Use index to get pointer for modification
						circuit := &torListGlobal[i_loop]; 
						if s, ok := updateStatus[circuit.Port]; ok { circuit.IsHealthy = s.IsHealthy; circuit.LastChecked = s.CheckedAt }
						if delPorts[circuit.Port] { 
							log.Printf("INFO: HealthCheck: Deleting %s (Port: %s). Error: %v", circuit.IPAddr, circuit.Port, updateStatus[circuit.Port].Error)
							circuit.DeleteCircuit(); deleted++ 
						} else { newList = append(newList, *circuit) } // Dereference pointer when appending copy
					}
					torListGlobal = newList; currentAfterDel := len(torListGlobal); needed := target - currentAfterDel
					if needed > 0 {
						log.Printf("INFO: HealthCheck: %d deleted. Current: %d, Target: %d. Replenishing %d.", deleted, currentAfterDel, target, needed)
						newCircs, errRep := tor.InitTor(appCtx, needed, *listenHost, *torExecutablePath, *baseTorrcFile, *torgoInstanceBasePath, *torExitNodes, *circuitRenewInterval, originalIPInfo, &currentPortUsage, mathRandGlobal, &mathRandMutex)
						if errRep != nil { log.Printf("ERROR: HealthCheck: Replenish error: %v", errRep) 
						} else if len(newCircs) > 0 { torListGlobal = append(torListGlobal, newCircs...); log.Printf("INFO: HealthCheck: Replenished %d. Total: %d.", len(newCircs), len(torListGlobal)) }
					}
					torListGlobalMutex.Unlock()
				} else { log.Printf("INFO: HealthCheck: All circuits healthy or no changes.") }
			}
		}
	}()

	stop := make(chan os.Signal, 1); signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() { 
		sig := <-stop; log.Printf("INFO: Shutdown (%v) received. Cleaning up...", sig); appCancel() 
		torListGlobalMutex.Lock(); log.Printf("INFO: Closing %d torgo Tor circuits...", len(torListGlobal)); 
		for i_shutdown := range torListGlobal { torListGlobal[i_shutdown].DeleteCircuit() }; 
		torListGlobal = []tor.TorStruct{}; 
		torListGlobalMutex.Unlock()
		log.Println("INFO: torgo cleanup complete. Exiting."); os.Exit(0)
	}()

	log.Printf("INFO: REST API server starting on port %s", *apiPort)
	if err := http.ListenAndServe(":"+*apiPort, router); err != nil { log.Fatalf("FATAL: API Server: %v", err) }
}

func handleSocksConnection(clientConn net.Conn) { 
	defer clientConn.Close(); 
	torListGlobalMutex.RLock()
	if len(torListGlobal) == 0 { torListGlobalMutex.RUnlock(); log.Printf("ERROR: SOCKS LB: No circuits."); return }
	currentCircuits := make([]tor.TorStruct, len(torListGlobal)); copy(currentCircuits, torListGlobal); 
	torListGlobalMutex.RUnlock()
	
	var selectedTor *tor.TorStruct; 
	healthyCircuits := make([]tor.TorStruct, 0, len(currentCircuits))
	for _, c := range currentCircuits { if c.IsHealthy { healthyCircuits = append(healthyCircuits, c) } }
	if len(healthyCircuits) == 0 { log.Printf("ERROR: SOCKS LB: No healthy circuits."); return }

	if *loadBalancerAlgo == "lc" { selectedTor = tor.GetTorLBWeight(healthyCircuits) 
	} else if *loadBalancerAlgo == "random" { selectedTor = tor.GetTorLBRandom(healthyCircuits, mathRandGlobal, &mathRandMutex) 
	} else { selectedTor = tor.GetTorLB(healthyCircuits) }
	
	if selectedTor == nil { log.Printf("ERROR: SOCKS LB: Circuit selection failed."); return }; 
	selectedTor.IncrementLoad()
	targetAddr := *listenHost + ":" + selectedTor.Port
	log.Printf("INFO: SOCKS LB: Client %s -> Tor %s (Port: %s, Country: %s, Load: %d)", clientConn.RemoteAddr(), selectedTor.IPAddr, selectedTor.Port, selectedTor.Country, selectedTor.GetLoad())
	torConn, err := net.DialTimeout("tcp", targetAddr, 15*time.Second); if err != nil { log.Printf("ERROR: SOCKS LB: Dial Tor %s: %v", targetAddr, err); return }; defer torConn.Close()
	errCh := make(chan error, 2); go func() { _, e := io.Copy(torConn, clientConn); errCh <- e }(); go func() { _, e := io.Copy(clientConn, torConn); errCh <- e }()
	for i := 0; i < 2; i++ { if err := <-errCh; err != nil { if !strings.Contains(err.Error(), "closed network") && !strings.Contains(err.Error(), "reset by peer") && !strings.Contains(err.Error(), "broken pipe") { log.Printf("WARN: SOCKS LB: io.Copy: %v", err) } } }
}
