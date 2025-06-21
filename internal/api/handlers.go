package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"torgo/internal/config"
	"torgo/internal/lb"
	"torgo/internal/tor"
)

// HealthzHandler provides a simple, built-in health check endpoint.
// It returns 200 OK if the load balancer can find at least one healthy backend instance.
// Otherwise, it returns 503 Service Unavailable.
func HealthzHandler(w http.ResponseWriter, r *http.Request, instances []*tor.Instance) {
	_, err := lb.GetNextHealthyInstance(instances)
	if err != nil {
		http.Error(w, "Service Unavailable: No healthy backend instances.", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "OK")
}

func RegisterAPIHandlers(mux *http.ServeMux, instances []*tor.Instance, appCfg *config.AppConfig) {
	// This is the main API router function that will be registered.
	masterRouter := func(w http.ResponseWriter, r *http.Request) {
		MasterAPIRouter(w, r, instances, appCfg)
	}

	// Register the master router for all /api/v1/ paths.
	mux.HandleFunc("/api/v1/", masterRouter)

	// Separately register the new healthz handler.
	mux.HandleFunc("/api/v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		HealthzHandler(w, r, instances)
	})
}

func firstNChars(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func AppDetailsHandler(w http.ResponseWriter, r *http.Request, appCfg *config.AppConfig) {
	details := map[string]interface{}{
		"num_instances":                          appCfg.NumTorInstances,
		"common_socks_port":                      appCfg.CommonSocksPort,
		"common_dns_port":                        appCfg.CommonDNSPort,
		"api_port":                               appCfg.APIPort,
		"rotation_stagger_delay_seconds":         int(appCfg.RotationStaggerDelay.Seconds()),
		"health_check_interval_seconds":          int(appCfg.HealthCheckInterval.Seconds()),
		"ip_diversity_check_interval_seconds":    int(appCfg.IPDiversityCheckInterval.Seconds()),
		"ip_diversity_rotation_cooldown_seconds": int(appCfg.IPDiversityRotationCooldown.Seconds()),
		"min_instances_for_ip_diversity_check":   appCfg.MinInstancesForIPDiversityCheck,
		"auto_rotation_enabled":                  appCfg.IsAutoRotationEnabled,
		"auto_rotate_circuit_interval_seconds":   int(appCfg.AutoRotateCircuitInterval.Seconds()),
		"auto_rotate_stagger_delay_seconds":      int(appCfg.AutoRotateStaggerDelay.Seconds()),
		"dns_cache_enabled":                      appCfg.DNSCacheEnabled,
		"dns_timeout_seconds":                    int(appCfg.DNSTimeout.Seconds()),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(details)
}

func rotateAllStaggeredHandler(w http.ResponseWriter, r *http.Request, instances []*tor.Instance, appCfg *config.AppConfig) {
	if !atomic.CompareAndSwapInt32(&appCfg.IsGlobalRotationActive, 0, 1) {
		http.Error(w, "A global rotation is already in progress.", http.StatusConflict)
		log.Println("API: Request for staggered rotation while one is active.")
		return
	}
	defer atomic.StoreInt32(&appCfg.IsGlobalRotationActive, 0)

	log.Println("API: Received request for STAGGERED rotation of all healthy Tor instances.")
	flusher, okFlusher := w.(http.Flusher)
	if okFlusher {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprintln(w, "Starting staggered rotation for all healthy instances...")
		flusher.Flush()
	} else {
		fmt.Fprintln(w, "Staggered rotation initiated. Monitor logs for progress.")
	}

	var healthyInstances []*tor.Instance
	for _, instance := range instances {
		if instance.IsCurrentlyHealthy() {
			healthyInstances = append(healthyInstances, instance)
		}
	}

	if len(healthyInstances) == 0 {
		log.Println("API: No healthy instances to rotate.")
		fmt.Fprintln(w, "No healthy instances found to rotate.")
		if okFlusher { flusher.Flush() }
		return
	}

	fmt.Fprintf(w, "Found %d healthy instances. Rotating with a %v delay between each...\n", len(healthyInstances), appCfg.RotationStaggerDelay)
	if okFlusher { flusher.Flush() }

	rotationCtx := r.Context()
	for i, instance := range healthyInstances {
		select {
		case <-rotationCtx.Done():
			log.Printf("API: Staggered rotation cancelled before instance %d.", instance.InstanceID)
			fmt.Fprintln(w, "Rotation cancelled.")
			if okFlusher { flusher.Flush() }
			return
		default:
		}
		fmt.Fprintf(w, "Rotating instance %d (%s)...\n", instance.InstanceID, instance.GetControlHost())
		if okFlusher { flusher.Flush() }

		response, err := instance.SendTorCommand("SIGNAL NEWNYM")
		if err != nil {
			fmt.Fprintf(w, "Error rotating instance %d: %v\n", instance.InstanceID, err)
		} else {
			fmt.Fprintf(w, "Instance %d NEWNYM response: %s\n", instance.InstanceID, firstNChars(response, 60))
			instance.SetExternalIP("", time.Time{})
		}
		if okFlusher { flusher.Flush() }

		if i < len(healthyInstances)-1 {
			select {
			case <-time.After(appCfg.RotationStaggerDelay):
			case <-rotationCtx.Done():
				fmt.Fprintln(w, "Rotation sleep interrupted.")
				if okFlusher { flusher.Flush() }
				return
			}
		}
	}
	fmt.Fprintln(w, "Staggered rotation process completed.")
	if okFlusher { flusher.Flush() }
}

func MasterAPIRouter(w http.ResponseWriter, r *http.Request, instances []*tor.Instance, appCfg *config.AppConfig) {
	path := r.URL.Path
	
	if path == "/api/v1/app-details" { AppDetailsHandler(w, r, appCfg); return }
	if path == "/api/v1/rotate-all-staggered" {
		if r.Method == http.MethodPost || r.Method == http.MethodGet {
			rotateAllStaggeredHandler(w, r, instances, appCfg)
		} else { http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed) }
		return
	}

	parts := strings.Split(strings.TrimPrefix(path, "/api/v1/"), "/")
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "tor") { http.NotFound(w, r); return }
	instanceIDStr := strings.TrimPrefix(parts[0], "tor")
	instanceID, err := strconv.Atoi(instanceIDStr)
	if err != nil || instanceID < 1 || instanceID > len(instances) {
		http.Error(w, "Invalid Tor instance ID", http.StatusBadRequest); return
	}
	instance := instances[instanceID-1]
	action := parts[1]

	switch action {
	case "rotate":
		if r.Method != http.MethodPost && r.Method != http.MethodGet { http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed); return }
		response, err := instance.SendTorCommand("SIGNAL NEWNYM")
		if err != nil { http.Error(w, fmt.Sprintf("Failed to rotate instance %d: %s", instance.InstanceID, err.Error()), http.StatusInternalServerError); return }
		instance.SetExternalIP("", time.Time{})
		fmt.Fprintf(w, "Instance %d NEWNYM response: %s", instance.InstanceID, firstNChars(response, 100))
	case "health":
		if r.Method != http.MethodGet { http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed); return }
		liveHealthy := instance.CheckHealth(r.Context())
		cachedHealthy, lastCheck, _ := instance.GetHealthStatus()
		respData := map[string]interface{}{ "instance_id": instance.InstanceID, "live_healthy_check_result": liveHealthy, "cached_is_healthy": cachedHealthy, "last_health_check_at": lastCheck.Format(time.RFC3339Nano)}
		w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(respData)
	case "stats":
		if r.Method != http.MethodGet { http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed); return }
		version, vErr := instance.SendTorCommand("GETINFO version")
		bootstrap, bErr := instance.SendTorCommand("GETINFO status/bootstrap-phase")
		trafficRead, trErr := instance.SendTorCommand("GETINFO traffic/read")
		trafficWritten, twErr := instance.SendTorCommand("GETINFO traffic/written")
		statsData := map[string]interface{}{
			"instance_id": instance.InstanceID,
			"version": strings.TrimSpace(version), "version_error": fmtError(vErr),
			"bootstrap_status": strings.TrimSpace(bootstrap), "bootstrap_error": fmtError(bErr),
			"traffic_read": strings.TrimSpace(trafficRead), "traffic_read_error": fmtError(trErr),
			"traffic_written": strings.TrimSpace(trafficWritten), "traffic_written_error": fmtError(twErr),
		}
		w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(statsData)
	case "ip":
		if r.Method != http.MethodGet { http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed); return }
		client := instance.GetHTTPClient()
		if client == nil { http.Error(w, fmt.Sprintf("HTTP client for instance %d not ready", instance.InstanceID), http.StatusServiceUnavailable); return }
		reqCtx, cancel := context.WithTimeout(r.Context(), appCfg.SocksTimeout*2+5*time.Second); defer cancel()
		httpReq, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, appCfg.IPCheckURL, nil)
		resp, err := client.Do(httpReq)
		if err != nil { http.Error(w, fmt.Sprintf("Failed to get IP via instance %d: %s", instance.InstanceID, err.Error()), http.StatusInternalServerError); return }
		defer resp.Body.Close()
		body, errRead := io.ReadAll(resp.Body)
		if errRead != nil { http.Error(w, fmt.Sprintf("Failed to read IP response body from instance %d: %s", instance.InstanceID, errRead.Error()), http.StatusInternalServerError); return }
		var ipJsonResponse struct { IP string `json:"IP"` }; var plainTextResponse string; isJsonResponse := false
		if errJson := json.Unmarshal(body, &ipJsonResponse); errJson == nil && ipJsonResponse.IP != "" {
			instance.SetExternalIP(ipJsonResponse.IP, time.Now()); isJsonResponse = true
		} else {
			trimmedBody := strings.TrimSpace(string(body))
			if net.ParseIP(trimmedBody) != nil { instance.SetExternalIP(trimmedBody, time.Now()); plainTextResponse = trimmedBody
			} else { log.Printf("Instance %d: IP response not valid: %s", instance.InstanceID, firstNChars(trimmedBody, 50)) }
		}
		currentIP, _, _ := instance.GetExternalIPInfo()
		if isJsonResponse { w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(map[string]string{"IP": currentIP})
		} else if plainTextResponse != "" { w.Header().Set("Content-Type", "text/plain"); fmt.Fprint(w, currentIP)
		} else { w.Header().Set("Content-Type", "text/plain"); fmt.Fprint(w, "Could not determine IP. Raw: "+string(body)) }
	case "config":
		if r.Method == http.MethodGet {
			cfgData := instance.GetConfigSnapshot()
			w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(cfgData)
		} else { http.Error(w, "Method Not Allowed (only GET)", http.StatusMethodNotAllowed) }
	default:
		http.NotFound(w, r)
	}
}

func fmtError(err error) string {
	if err == nil { return "" }
	return err.Error()
}