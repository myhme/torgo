package api // Correct package declaration

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	mrand "math/rand" // Alias for math/rand
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"

	// Import your internal packages
	"torgo/internal/adblock"
	"torgo/internal/tor"
)

// APIHandlers holds dependencies for API handlers.
// This struct will be initialized in main.go.
type APIHandlers struct {
	// Tor related state (pointers to globals in main.go)
	TorListGlobal      *[]tor.TorStruct // Use tor.TorStruct
	TorListGlobalMutex *sync.RWMutex
	ListenHost         *string
	SocksLBPort        *string

	// Tor instance creation parameters (pointers to globals/flags in main.go)
	TorExecutablePath     *string
	BaseTorrcFile         *string
	TorgoInstanceBasePath *string
	TorExitNodes          *string
	CircuitRenewInterval  *int
	OriginalIPInfo        *tor.IpinfoIo // Use tor.IpinfoIo
	CurrentPortUsage      *atomic.Int32
	MathRandGlobal        *mrand.Rand
	MathRandMutex         *sync.Mutex
	AppCtx                context.Context // Main application context

	// API Access Key (pointer to global in main.go)
	APIAccessKey *string

	// Adblock related state (pointers to globals in main.go)
	CurrentAdblockURLs              *[]string
	CurrentAdblockURLsMutex         *sync.RWMutex
	CurrentAdblockInterval          *time.Duration
	LastAdblockSuccessfulUpdateTime *time.Time
	AdblockUpdateInProgressMutex    *sync.Mutex
	AdblockManagedHostsFile         *string
}

// NewAPIHandlers creates a new APIHandlers struct.
// This function would be called in main.go to initialize the handlers with dependencies.
func NewAPIHandlers(
	torList *[]tor.TorStruct, torListMutex *sync.RWMutex, listenHost, socksLBPort *string,
	torExe *string, baseTorrc, torgoInstanceBase, exitNodes *string, renewInterval *int,
	origIP *tor.IpinfoIo, portUsage *atomic.Int32, mRand *mrand.Rand, mRandMutex *sync.Mutex, appCtx context.Context,
	apiKey *string,
	adblockURLs *[]string, adblockURLsMutex *sync.RWMutex, adblockInterval *time.Duration,
	lastAdblockUpdate *time.Time, adblockUpdateMutex *sync.Mutex, adblockHostsFile *string,
) *APIHandlers {
	return &APIHandlers{
		TorListGlobal:      torList, TorListGlobalMutex: torListMutex, ListenHost: listenHost,
		SocksLBPort: socksLBPort,
		TorExecutablePath: torExe, BaseTorrcFile: baseTorrc, TorgoInstanceBasePath: torgoInstanceBase,
		TorExitNodes: exitNodes, CircuitRenewInterval: renewInterval, OriginalIPInfo: origIP,
		CurrentPortUsage: portUsage, MathRandGlobal: mRand, MathRandMutex: mRandMutex, AppCtx: appCtx,
		APIAccessKey: apiKey,
		CurrentAdblockURLs: adblockURLs, CurrentAdblockURLsMutex: adblockURLsMutex,
		CurrentAdblockInterval: adblockInterval, LastAdblockSuccessfulUpdateTime: lastAdblockUpdate,
		AdblockUpdateInProgressMutex: adblockUpdateMutex, AdblockManagedHostsFile: adblockHostsFile,
	}
}


// --- WebUI Handler ---
func (h *APIHandlers) ServeWebUI(webuiDir string) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		http.ServeFile(rw, r, filepath.Join(webuiDir, "webui.html"))
	}
}

func (h *APIHandlers) ServeStatic(webuiDir string) http.Handler {
	return http.StripPrefix("/webui/", http.FileServer(http.Dir(webuiDir)))
}

// --- Tor Circuit API Handlers ---
func (h *APIHandlers) GetCircuitsAPIHandler(w http.ResponseWriter, r *http.Request) {
	h.TorListGlobalMutex.RLock()
	currentTorListSnapshot := make([]tor.TorStruct, len(*h.TorListGlobal))
	copy(currentTorListSnapshot, *h.TorListGlobal)
	h.TorListGlobalMutex.RUnlock()

	responseMap := tor.TortoMap(currentTorListSnapshot, *h.ListenHost) // Use tor.TortoMap
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if err := json.NewEncoder(w).Encode(responseMap); err != nil {
		log.Printf("ERROR: [api] Failed to encode circuit info: %v", err)
		http.Error(w, "Failed to encode circuit info", http.StatusInternalServerError)
	}
}

func (h *APIHandlers) AddCircuitsAPIHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	newReqStr, ok := vars["new"]
	if !ok { http.Error(w, "Missing number of circuits", http.StatusBadRequest); return }
	numToAdd, err := strconv.Atoi(newReqStr)
	if err != nil || numToAdd <= 0 { http.Error(w, "Invalid number of circuits", http.StatusBadRequest); return }

	go func(n int) {
		log.Printf("INFO: [api] Adding %d new Tor circuits asynchronously via API", n)
		// Use tor.InitTor
		newlyAdded, errAdd := tor.InitTor(h.AppCtx, n, *h.ListenHost, *h.TorExecutablePath, *h.BaseTorrcFile, *h.TorgoInstanceBasePath, *h.TorExitNodes, *h.CircuitRenewInterval, *h.OriginalIPInfo, h.CurrentPortUsage, h.MathRandGlobal, h.MathRandMutex)
		if errAdd != nil { log.Printf("ERROR: [api] Async add %d circuits failed: %v", n, errAdd); return }
		
		if len(newlyAdded) > 0 {
			h.TorListGlobalMutex.Lock()
			*h.TorListGlobal = append(*h.TorListGlobal, newlyAdded...)
			log.Printf("INFO: [api] Async add: Added %d circuits. Total now: %d. PortUsage: %d", len(newlyAdded), len(*h.TorListGlobal), h.CurrentPortUsage.Load())
			h.TorListGlobalMutex.Unlock()
		}
	}(numToAdd)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": fmt.Sprintf("Request to add %d circuits accepted.", numToAdd)})
}

func (h *APIHandlers) DeleteCircuitsByPortAPIHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	portsStr, ok := vars["port"]
	if !ok { http.Error(w, "Missing port(s)", http.StatusBadRequest); return }
	portsToDel := strings.Split(portsStr, ",")
	log.Printf("INFO: [api] Request to delete Tor circuits by Port(s): %v", portsToDel)

	h.TorListGlobalMutex.Lock()
	newList := make([]tor.TorStruct, 0, len(*h.TorListGlobal))
	deletedCount := 0
	for _, circuit := range *h.TorListGlobal { // Iterate over value, not pointer
		isToDelete := false
		for _, pDel := range portsToDel {
			if circuit.Port == strings.TrimSpace(pDel) {
				// circuit is a copy here, so calling DeleteCircuit on it won't affect the original Cmd.
				// We need to find the original in *h.TorListGlobal to call DeleteCircuit correctly,
				// or DeleteCircuit must be a function that takes necessary info.
				// For now, let's assume DeleteCircuit on the copy is for logging/intent,
				// and the actual process kill happens via the original TorStruct's Cmd.
				// A better way: pass the pointer or index to a delete function.

				// Find the actual circuit in the global list to call DeleteCircuit on its Cmd
				for i_orig := range *h.TorListGlobal {
					if (*h.TorListGlobal)[i_orig].Port == circuit.Port {
						(*h.TorListGlobal)[i_orig].DeleteCircuit() 
						break
					}
				}
				deletedCount++
				isToDelete = true; break
			}
		}
		if !isToDelete { newList = append(newList, circuit) }
	}
	*h.TorListGlobal = newList
	log.Printf("INFO: [api] Deleted %d circuits by Port. Total now: %d", deletedCount, len(*h.TorListGlobal))
	
	currentSnapshot := make([]tor.TorStruct, len(*h.TorListGlobal))
	copy(currentSnapshot, *h.TorListGlobal)
	h.TorListGlobalMutex.Unlock() 

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tor.TortoMap(currentSnapshot, *h.ListenHost)) // Use tor.TortoMap
}

// --- Adblock API Handlers ---
func (h *APIHandlers) GetAdblockConfigAPIHandler(w http.ResponseWriter, r *http.Request) {
	h.CurrentAdblockURLsMutex.RLock()
	urlsCopy := make([]string, len(*h.CurrentAdblockURLs))
	copy(urlsCopy, *h.CurrentAdblockURLs)
	h.CurrentAdblockURLsMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"urls":                    urlsCopy,
		"update_interval_seconds": h.CurrentAdblockInterval.Seconds(),
		"last_update_time":        h.LastAdblockSuccessfulUpdateTime.Format(time.RFC3339),
	})
}

func (h *APIHandlers) TriggerAdblockUpdateAPIHandler(w http.ResponseWriter, r *http.Request) {
	// Use adblock.UpdateAdblockListsAndReloadDnsmasq
	go func() {
		_, _, err := adblock.UpdateAdblockListsAndReloadDnsmasq(h.AppCtx, *h.CurrentAdblockURLs, *h.AdblockManagedHostsFile, h.AdblockUpdateInProgressMutex)
		if err != nil {
			log.Printf("ERROR: [api] Triggered adblock update failed: %v", err)
		}
		// Update last update time, even on failure, to reflect attempt
		h.AdblockUpdateInProgressMutex.Lock() // Protect this global write
		*h.LastAdblockSuccessfulUpdateTime = time.Now()
		h.AdblockUpdateInProgressMutex.Unlock()
	}()
	
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "Adblock list update triggered."})
}

func (h *APIHandlers) AddAdblockURLAPIHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct { URL string `json:"url"` }
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error": "Invalid payload"}`, http.StatusBadRequest); return
	}
	trimmedURL := strings.TrimSpace(payload.URL)
	if trimmedURL == "" { http.Error(w, `{"error": "URL empty"}`, http.StatusBadRequest); return }

	h.CurrentAdblockURLsMutex.Lock()
	exists := false
	for _, u := range *h.CurrentAdblockURLs { if u == trimmedURL { exists = true; break } }
	if !exists { *h.CurrentAdblockURLs = append(*h.CurrentAdblockURLs, trimmedURL); log.Printf("INFO: [api] Added adblock URL: %s", trimmedURL)
	} else { log.Printf("INFO: [api] Adblock URL exists: %s", trimmedURL) }
	
	urlsCopy := make([]string, len(*h.CurrentAdblockURLs)); copy(urlsCopy, *h.CurrentAdblockURLs)
	h.CurrentAdblockURLsMutex.Unlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "URL processed", "current_urls": urlsCopy})
}

func (h *APIHandlers) DeleteAdblockURLAPIHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct { URL string `json:"url"` }
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error": "Invalid payload"}`, http.StatusBadRequest); return
	}
	urlToRemove := strings.TrimSpace(payload.URL)
	if urlToRemove == "" { http.Error(w, `{"error": "URL empty"}`, http.StatusBadRequest); return }

	h.CurrentAdblockURLsMutex.Lock()
	newURLs := []string{}; found := false
	for _, u := range *h.CurrentAdblockURLs { if u == urlToRemove { found = true } else { newURLs = append(newURLs, u) } }
	*h.CurrentAdblockURLs = newURLs
	
	urlsCopy := make([]string, len(*h.CurrentAdblockURLs)); copy(urlsCopy, *h.CurrentAdblockURLs)
	h.CurrentAdblockURLsMutex.Unlock()

	if found {
		log.Printf("INFO: [api] Removed adblock URL: %s", urlToRemove)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "URL removed", "current_urls": urlsCopy})
	} else { http.Error(w, `{"error": "URL not found"}`, http.StatusNotFound) }
}

// --- Root and Auth Middleware ---
func (h *APIHandlers) RootAPIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"Socks5Proxy":      fmt.Sprintf("socks5://%s:%s", *h.ListenHost, *h.SocksLBPort),
		"WebUI":            "/webui",
		"APICircuits":      "/api/circuits",
		"APIAdblockConfig": "/api/adblock/config",
		"APIAdblockUpdate": "/api/adblock/update (POST, authenticated)",
		"Adblocking":       "Handled by system-wide dnsmasq via Tor DNS",
	})
}

func (h *APIHandlers) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *h.APIAccessKey == "" || r.Header.Get("access_key") == *h.APIAccessKey {
			next.ServeHTTP(w, r)
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, `{"error": "Unauthorized"}`)
		}
	})
}
