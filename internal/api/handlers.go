package api

import (
	"embed"
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
	"context" // Keep, it's used by http.Request

	"torgo/internal/config"
	"torgo/internal/torinstance"
)

//go:embed webui.html
var webUIContent embed.FS

func firstNChars(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func WebUIHandler(w http.ResponseWriter, r *http.Request) {
	// ... (same as before)
	if r.URL.Path != "/webui" && r.URL.Path != "/webui/" {
		http.NotFound(w, r)
		return
	}

	htmlContent, err := webUIContent.ReadFile("webui.html")
	if err != nil {
		log.Printf("Error reading embedded webui.html: %v", err)
		http.Error(w, "Internal Server Error: Could not load Web UI.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(htmlContent)
}

func AppDetailsHandler(w http.ResponseWriter, r *http.Request, appCfg *config.AppConfig) {
	details := map[string]interface{}{
		"num_instances":             appCfg.NumTorInstances,
		"common_socks_port":         appCfg.CommonSocksPort,
		"common_dns_port":           appCfg.CommonDNSPort,
		"api_port":                  appCfg.APIPort,
		"load_balancing_strategy":   appCfg.LoadBalancingStrategy,
		"rotation_stagger_delay_seconds": int(appCfg.RotationStaggerDelay.Seconds()), // Manual API stagger
		"health_check_interval_seconds": int(appCfg.HealthCheckInterval.Seconds()),
		
		// Circuit Manager related config
		"circuit_manager_enabled": appCfg.CircuitManagerEnabled,
		"circuit_max_age_seconds": int(appCfg.CircuitMaxAge.Seconds()),
		"circuit_rotation_stagger_seconds": int(appCfg.CircuitRotationStagger.Seconds()),
		"ip_diversity_check_enabled": appCfg.IPDiversityCheckEnabled,
		"ip_diversity_min_instances": appCfg.IPDiversityMinInstances,
		"ip_diversity_subnet_check_interval_seconds": int(appCfg.IPDiversitySubnetCheckInterval.Seconds()),
		"ip_diversity_rotation_cooldown_seconds": int(appCfg.IPDiversityRotationCooldown.Seconds()),

		// Performance Test related config
		"perf_test_enabled": appCfg.PerfTestEnabled,
		"perf_test_interval_seconds": int(appCfg.PerfTestInterval.Seconds()),
		"latency_test_targets": appCfg.LatencyTestTargets, // map[string]string
		"speed_test_target_url": appCfg.SpeedTestTargetURL,
		"speed_test_target_bytes": appCfg.SpeedTestTargetBytes,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(details)
}

func rotateAllStaggeredHandler(w http.ResponseWriter, r *http.Request, instances []*torinstance.Instance, appCfg *config.AppConfig) {
	// ... (same as before, uses appCfg.RotationStaggerDelay for manual API triggered rotation)
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
		flusher.Flush()
	} else {
		log.Println("Warning: ResponseWriter does not support flushing for staggered rotation progress.")
	}

	fmt.Fprintln(w, "Starting staggered rotation for all healthy instances...")
	if okFlusher {	flusher.Flush() }

	var healthyInstances []*torinstance.Instance
	for _, instance := range instances {
		instance.Mu.Lock()
		isHealthy := instance.IsHealthy
		instance.Mu.Unlock()
		if isHealthy {
			healthyInstances = append(healthyInstances, instance)
		}
	}

	if len(healthyInstances) == 0 {
		log.Println("API: No healthy instances to rotate.")
		fmt.Fprintln(w, "No healthy instances found to rotate.")
		if okFlusher { flusher.Flush() }
		return
	}

	log.Printf("API: Found %d healthy instances for staggered rotation.", len(healthyInstances))
	fmt.Fprintf(w, "Found %d healthy instances. Rotating with a %v delay between each...\n", len(healthyInstances), appCfg.RotationStaggerDelay)
	if okFlusher { flusher.Flush() }

	for i, instance := range healthyInstances {
		select {
		case <-r.Context().Done():
			log.Printf("API: Staggered rotation cancelled by client disconnect before instance %d.", instance.InstanceID)
			fmt.Fprintln(w, "Rotation cancelled by client.")
			if okFlusher { flusher.Flush() }
			return
		default:
		}
		log.Printf("API: Staggered rotation: Rotating instance %d (%s)", instance.InstanceID, instance.ControlHost)
		fmt.Fprintf(w, "Rotating instance %d (%s)...\n", instance.InstanceID, instance.ControlHost)
		if okFlusher { flusher.Flush() }

		// true to update LastCircuitRecreationTime
		response, err := instance.SendTorCommand("SIGNAL NEWNYM", true)
		if err != nil {
			log.Printf("API: Staggered rotation: Error rotating instance %d: %v", instance.InstanceID, err)
			fmt.Fprintf(w, "Error rotating instance %d: %v\n", instance.InstanceID, err)
		} else {
			log.Printf("API: Staggered rotation: Instance %d NEWNYM response: %s", instance.InstanceID, firstNChars(response, 60))
			fmt.Fprintf(w, "Instance %d NEWNYM response: %s\n", instance.InstanceID, firstNChars(response, 60))
		}
		if okFlusher { flusher.Flush() }

		if i < len(healthyInstances)-1 {
			log.Printf("API: Staggered rotation: Sleeping for %v before next instance.", appCfg.RotationStaggerDelay)
			select {
			case <-time.After(appCfg.RotationStaggerDelay):
			case <-r.Context().Done():
				log.Printf("API: Staggered rotation sleep interrupted by client disconnect for instance %d.", instance.InstanceID)
				fmt.Fprintln(w, "Rotation sleep interrupted by client.")
				if okFlusher { flusher.Flush() }
				return
			}
		}
	}
	log.Println("API: Staggered rotation completed for all healthy instances.")
	fmt.Fprintln(w, "Staggered rotation process completed.")
	if okFlusher { flusher.Flush() }
}

func MasterAPIRouter(w http.ResponseWriter, r *http.Request, instances []*torinstance.Instance, appCfg *config.AppConfig) {
	path := r.URL.Path

	if path == "/api/v1/app-details" {
		AppDetailsHandler(w, r, appCfg)
		return
	}
	if path == "/api/v1/rotate-all-staggered" {
		if r.Method == http.MethodPost || r.Method == http.MethodGet { // Allow GET for simplicity
			rotateAllStaggeredHandler(w, r, instances, appCfg)
		} else {
			http.Error(w, "Method Not Allowed for /rotate-all-staggered", http.StatusMethodNotAllowed)
		}
		return
	}

	parts := strings.Split(strings.TrimPrefix(path, "/api/v1/"), "/")
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "tor") {
		http.NotFound(w, r)
		return
	}

	instanceIDStr := strings.TrimPrefix(parts[0], "tor")
	instanceID, err := strconv.Atoi(instanceIDStr)
	if err != nil || instanceID < 1 || instanceID > len(instances) {
		http.Error(w, "Invalid Tor instance ID in path", http.StatusBadRequest)
		return
	}
	instance := instances[instanceID-1] // 0-indexed
	action := parts[1]

	switch action {
	case "rotate":
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		// true to update LastCircuitRecreationTime
		response, err := instance.SendTorCommand("SIGNAL NEWNYM", true)
		if err != nil {
			http.Error(w, "Failed to rotate instance "+instanceIDStr+": "+err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Instance %d NEWNYM: %s", instance.InstanceID, response)

	case "health":
		// ... (same as before)
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		liveHealthy := instance.CheckHealth(r.Context()) 
		instance.Mu.Lock()
		cachedHealthy := instance.IsHealthy 
		lastCheck := instance.LastHealthCheck
		instance.Mu.Unlock()

		respData := map[string]interface{}{
			"instance_id":                 instance.InstanceID,
			"live_healthy_check_result": liveHealthy, 
			"cached_is_healthy":           cachedHealthy, 
			"last_health_check_at":        lastCheck.Format(time.RFC3339Nano),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(respData)


	case "stats": // Basic Tor stats
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		// false for updateCircuitTimeOnNewnym as GETINFO doesn't trigger NEWNYM
		version, vErr := instance.SendTorCommand("GETINFO version", false)
		bootstrap, bErr := instance.SendTorCommand("GETINFO status/bootstrap-phase", false)
		trafficRead, trErr := instance.SendTorCommand("GETINFO traffic/read", false)
		trafficWritten, twErr := instance.SendTorCommand("GETINFO traffic/written", false)

		statsData := map[string]interface{}{
			"instance_id":           instance.InstanceID,
			"active_proxy_connections": instance.GetActiveProxyConnections(),
			"version":               version, "version_error": fmtError(vErr),
			"bootstrap_status":      bootstrap, "bootstrap_error": fmtError(bErr),
			"traffic_read":          trafficRead, "traffic_read_error": fmtError(trErr),
			"traffic_written":       trafficWritten, "traffic_written_error": fmtError(twErr),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(statsData)

	case "ip": // Get external IP via this instance
		// ... (same as before)
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		client := instance.GetHTTPClient()
		if client == nil {
			http.Error(w, "HTTP client for instance "+instanceIDStr+" not ready", http.StatusServiceUnavailable)
			return
		}

		reqCtx, cancel := context.WithTimeout(r.Context(), appCfg.SocksTimeout*2+5*time.Second)
		defer cancel()

		httpReq, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, appCfg.IPCheckURL, nil)
		resp, err := client.Do(httpReq)
		if err != nil {
			http.Error(w, "Failed to get IP via instance "+instanceIDStr+": "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		body, errRead := io.ReadAll(resp.Body)
		if errRead != nil {
			http.Error(w, "Failed to read IP response body from instance "+instanceIDStr+": "+errRead.Error(), http.StatusInternalServerError)
			return
		}

		var ipJsonResponse struct {	IP string `json:"IP"`; IsTor bool `json:"IsTor"` }
		var plainTextResponse string
		isJsonResponse := false

		if errJson := json.Unmarshal(body, &ipJsonResponse); errJson == nil && ipJsonResponse.IP != "" {
			instance.SetExternalIP(ipJsonResponse.IP)
			isJsonResponse = true
		} else {
			trimmedBody := strings.TrimSpace(string(body))
			if net.ParseIP(trimmedBody) != nil {
				instance.SetExternalIP(trimmedBody)
				plainTextResponse = trimmedBody
			} else {
				log.Printf("Instance %d: IP response was not valid JSON with IP field, nor a plain IP: %s", instance.InstanceID, firstNChars(trimmedBody, 50))
			}
		}

		if isJsonResponse {
			w.Header().Set("Content-Type", "application/json")
			w.Write(body)
		} else if plainTextResponse != "" {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, plainTextResponse)
		} else {
			originalContentType := resp.Header.Get("Content-Type")
			if originalContentType == "" {	originalContentType = "text/plain" }
			w.Header().Set("Content-Type", originalContentType)
			w.Write(body)
		}


	case "config": // Get or Set instance-specific Tor configurations (like SOCKS port, or node policies)
		handleInstanceConfig(w, r, instance, parts, appCfg)
	
	case "performancemetrics": // New endpoint to get performance data
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		metrics := instance.GetPerfMetrics()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metrics)


	default:
		http.NotFound(w, r)
	}
}

// handleInstanceConfig now also handles GET /api/v1/tor<id>/config/nodepolicy
// and POST /api/v1/tor<id>/config/nodepolicy
func handleInstanceConfig(w http.ResponseWriter, r *http.Request, instance *torinstance.Instance, pathParts []string, appCfg *config.AppConfig) {
	if len(pathParts) > 2 { // SET actions like .../config/socksport or .../config/nodepolicy
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed for setting config", http.StatusMethodNotAllowed)
			return
		}
		subAction := pathParts[2]

		switch subAction {
		case "socksport", "dnsport", "controlport": // Existing port settings
			var reqBody struct { Address string `json:"address"`; Port int `json:"port"`	}
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				http.Error(w, "Invalid JSON request body for port config: "+err.Error(), http.StatusBadRequest)
				return
			}
			defer r.Body.Close()
			// ... (rest of port setting logic from previous version) ...
			if reqBody.Port < 0 || reqBody.Port > 65535 {
				http.Error(w, "Invalid port number.", http.StatusBadRequest)
				return
			}
			newPortStr := strconv.Itoa(reqBody.Port)
			listenAddress := "127.0.0.1"
			if reqBody.Address != "" {	listenAddress = reqBody.Address }

			var torConfigKey, fullAddressToSet string
			switch subAction {
			case "socksport":
				if reqBody.Port == 0 { http.Error(w, "SocksPort cannot be 0.", http.StatusBadRequest); return }
				torConfigKey = "SocksPort"; fullAddressToSet = net.JoinHostPort(listenAddress, newPortStr)
			case "dnsport":
				torConfigKey = "DNSPort"; 
				if reqBody.Port == 0 { fullAddressToSet = "0" } else { fullAddressToSet = net.JoinHostPort(listenAddress, newPortStr) }
			case "controlport":
				if reqBody.Port == 0 { http.Error(w, "ControlPort cannot be 0.", http.StatusBadRequest); return }
				torConfigKey = "ControlPort"; fullAddressToSet = net.JoinHostPort(listenAddress, newPortStr)
				fmt.Fprintln(w, "WARNING: Changing ControlPort is high-risk.")
			default: http.Error(w, "Unknown port config action", http.StatusBadRequest); return
			}
			
			// false for updateCircuitTimeOnNewnym as SETCONF doesn't trigger NEWNYM
			response, err := instance.SendTorCommand(fmt.Sprintf("SETCONF %s %s", torConfigKey, fullAddressToSet), false)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to set %s: %v", torConfigKey, err), http.StatusInternalServerError)
				return
			}
			if !strings.Contains(response, "250 OK") {
				http.Error(w, fmt.Sprintf("Tor rejected %s change: %s", torConfigKey, response), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, "Instance %d: %s set to %s. Tor response: %s\n", instance.InstanceID, torConfigKey, fullAddressToSet, response)
			instance.Mu.Lock()
			switch subAction {
			case "socksport": instance.BackendSocksHost = fullAddressToSet; go instance.ReinitializeHTTPClient()
			case "dnsport": instance.BackendDNSHost = fullAddressToSet
			case "controlport": instance.ControlHost = fullAddressToSet; instance.CloseControlConnUnlocked()
			}
			instance.Mu.Unlock()
			fmt.Fprintf(w, "API internal state for instance %d updated.\n", instance.InstanceID)


		case "nodepolicy": // New: POST /api/v1/tor<id>/config/nodepolicy
			var policyReq struct {
				PolicyType string `json:"policy_type"` // "ExitNodes", "EntryNodes", "ExcludeNodes"
				Nodes      string `json:"nodes"`       // Comma-separated list, or empty to clear/reset
			}
			if err := json.NewDecoder(r.Body).Decode(&policyReq); err != nil {
				http.Error(w, "Invalid JSON for node policy: "+err.Error(), http.StatusBadRequest)
				return
			}
			defer r.Body.Close()

			if policyReq.PolicyType != "ExitNodes" && policyReq.PolicyType != "EntryNodes" && policyReq.PolicyType != "ExcludeNodes" {
				http.Error(w, "Invalid policy_type. Must be ExitNodes, EntryNodes, or ExcludeNodes.", http.StatusBadRequest)
				return
			}

			// Basic validation for nodes (e.g. country codes are typically 2 letters, fingerprints are 40 hex chars)
			// This is not exhaustive. Tor will do the final validation.
			// For simplicity, we'll pass it through.

			response, err := instance.SetTorNodePolicy(policyReq.PolicyType, policyReq.Nodes)
			if err != nil {
				log.Printf("API: Instance %d: Error setting node policy %s to '%s': %v. Tor response: %s", instance.InstanceID, policyReq.PolicyType, policyReq.Nodes, err, response)
				http.Error(w, fmt.Sprintf("Error setting Tor node policy %s: %v. Tor response: %s", policyReq.PolicyType, err, response), http.StatusInternalServerError)
				return
			}
			log.Printf("API: Instance %d: Successfully set node policy %s to '%s'. Tor response: %s", instance.InstanceID, policyReq.PolicyType, policyReq.Nodes, response)
			fmt.Fprintf(w, "Instance %d: Node policy %s set to '%s'. Tor response: %s", instance.InstanceID, policyReq.PolicyType, policyReq.Nodes, response)


		default:
			http.Error(w, "Unknown config set action: "+subAction, http.StatusBadRequest)
		}

	} else { // GET /api/v1/tor<id>/config  (General instance config and status)
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		instance.Mu.Lock()
		// Get current node policies from Tor directly for the most up-to-date view
		// This can be slow if done for many instances frequently.
		// Consider caching or having a separate endpoint if it becomes an issue.
		liveNodePolicies, errNP := instance.GetTorNodePolicies()
		if errNP != nil {
			log.Printf("API: Instance %d: Error fetching live node policies for config display: %v", instance.InstanceID, errNP)
			// Proceed without them or show error for those fields
		}

		cfgData := map[string]interface{}{
			"instance_id":                 instance.InstanceID,
			"control_host":                instance.ControlHost,
			"backend_socks_host":          instance.BackendSocksHost,
			"backend_dns_host":            instance.BackendDNSHost,
			"is_healthy":                  instance.IsHealthy,
			"last_health_check_at":        instance.LastHealthCheck.Format(time.RFC3339Nano),
			"external_ip":                 instance.ExternalIP,
			"last_ip_check_at":            instance.LastIPCheck.Format(time.RFC3339Nano),
			"last_ip_change_at":           instance.LastIPChangeTime.Format(time.RFC3339Nano),
			"last_circuit_recreation_at":  instance.LastCircuitRecreationTime.Format(time.RFC3339Nano),
			"last_diversity_rotate_at":    instance.LastDiversityRotate.Format(time.RFC3339Nano),
			"active_proxy_connections":    instance.GetActiveProxyConnections(),
			"auth_cookie_path":            instance.AuthCookiePath,
			"data_dir":                    instance.DataDir,
			// Include current node policies (could be from cache or live)
			"current_exitnode_policy":  liveNodePolicies["ExitNodes"], // instance.CurrentExitNodePolicy, (use live)
			"current_entrynode_policy": liveNodePolicies["EntryNodes"], // instance.CurrentEntryNodePolicy,
			"current_excludenode_policy": liveNodePolicies["ExcludeNodes"],
			"current_geoip_file": liveNodePolicies["GeoIPFile"],
			"current_geoip6_file": liveNodePolicies["GeoIPv6File"],
			// Performance metrics are now in their own endpoint, but could be included here too if desired
			// "performance_metrics": instance.GetPerfMetrics(),
		}
		instance.Mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfgData)
	}
}


func fmtError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
