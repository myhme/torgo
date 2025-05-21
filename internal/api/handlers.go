package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog" // Import slog
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"context"

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

// WebUIHandler serves the embedded web UI.
func WebUIHandler(w http.ResponseWriter, r *http.Request) {
	htmlContent, err := webUIContent.ReadFile("webui.html")
	if err != nil {
		slog.Error("Error reading embedded webui.html", slog.Any("error", err))
		http.Error(w, "Internal Server Error: Could not load Web UI.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(htmlContent)
}

// AppDetailsHandler provides application configuration details.
func AppDetailsHandler(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		details := map[string]interface{}{
			"num_instances":             appCfg.NumTorInstances,
			"common_socks_port":         appCfg.CommonSocksPort,
			"common_dns_port":           appCfg.CommonDNSPort,
			"api_port":                  appCfg.APIPort,
			"load_balancing_strategy":   appCfg.LoadBalancingStrategy,
			"rotation_stagger_delay_seconds": int(appCfg.RotationStaggerDelay.Seconds()),
			"health_check_interval_seconds": int(appCfg.HealthCheckInterval.Seconds()),
			"circuit_manager_enabled": appCfg.CircuitManagerEnabled,
			"circuit_max_age_seconds": int(appCfg.CircuitMaxAge.Seconds()),
			"circuit_rotation_stagger_seconds": int(appCfg.CircuitRotationStagger.Seconds()),
			"ip_diversity_check_enabled": appCfg.IPDiversityCheckEnabled,
			"ip_diversity_min_instances": appCfg.IPDiversityMinInstances,
			"ip_diversity_subnet_check_interval_seconds": int(appCfg.IPDiversitySubnetCheckInterval.Seconds()),
			"ip_diversity_rotation_cooldown_seconds": int(appCfg.IPDiversityRotationCooldown.Seconds()),
			"perf_test_enabled": appCfg.PerfTestEnabled,
			"perf_test_interval_seconds": int(appCfg.PerfTestInterval.Seconds()),
			"latency_test_targets": appCfg.LatencyTestTargets,
			"speed_test_target_url": appCfg.SpeedTestTargetURL,
			"speed_test_target_bytes": appCfg.SpeedTestTargetBytes,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(details)
	}
}

// RotateAllStaggeredHandler handles requests to rotate all healthy Tor circuits.
// Renamed from rotateAllStaggeredHandler to be exported.
func RotateAllStaggeredHandler(instances []*torinstance.Instance, appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !atomic.CompareAndSwapInt32(&appCfg.IsGlobalRotationActive, 0, 1) {
			slog.Warn("API: Staggered rotation request denied, another is active.", "remote_addr", r.RemoteAddr)
			http.Error(w, "A global rotation is already in progress.", http.StatusConflict)
			return
		}
		defer atomic.StoreInt32(&appCfg.IsGlobalRotationActive, 0)

		slog.Info("API: Received request for STAGGERED rotation of all healthy Tor instances.", "remote_addr", r.RemoteAddr)
		
		flusher, okFlusher := w.(http.Flusher)
		if okFlusher {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			flusher.Flush()
		} else {
			slog.Warn("ResponseWriter does not support flushing for staggered rotation progress.")
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
			slog.Info("API: No healthy instances to rotate.")
			fmt.Fprintln(w, "No healthy instances found to rotate.")
			if okFlusher { flusher.Flush() }
			return
		}

		slog.Info("API: Found healthy instances for staggered rotation.", "count", len(healthyInstances))
		fmt.Fprintf(w, "Found %d healthy instances. Rotating with a %v delay between each...\n", len(healthyInstances), appCfg.RotationStaggerDelay)
		if okFlusher { flusher.Flush() }

		for i, instance := range healthyInstances {
			select {
			case <-r.Context().Done():
				slog.Info("API: Staggered rotation cancelled by client disconnect.", "instance_id", instance.InstanceID, "remote_addr", r.RemoteAddr)
				fmt.Fprintln(w, "Rotation cancelled by client.")
				if okFlusher { flusher.Flush() }
				return
			default:
			}
			slog.Info("API: Staggered rotation: Rotating instance.", "instance_id", instance.InstanceID, "control_host", instance.ControlHost)
			fmt.Fprintf(w, "Rotating instance %d (%s)...\n", instance.InstanceID, instance.ControlHost)
			if okFlusher { flusher.Flush() }

			response, err := instance.SendTorCommand("SIGNAL NEWNYM", true)
			if err != nil {
				slog.Error("API: Staggered rotation: Error rotating instance.", "instance_id", instance.InstanceID, slog.Any("error", err))
				fmt.Fprintf(w, "Error rotating instance %d: %v\n", instance.InstanceID, err)
			} else {
				slog.Info("API: Staggered rotation: Instance NEWNYM response.", "instance_id", instance.InstanceID, "response", firstNChars(response, 60))
				fmt.Fprintf(w, "Instance %d NEWNYM response: %s\n", instance.InstanceID, firstNChars(response, 60))
			}
			if okFlusher { flusher.Flush() }

			if i < len(healthyInstances)-1 {
				slog.Debug("API: Staggered rotation: Sleeping before next instance.", "delay", appCfg.RotationStaggerDelay)
				select {
				case <-time.After(appCfg.RotationStaggerDelay):
				case <-r.Context().Done():
					slog.Info("API: Staggered rotation sleep interrupted by client disconnect.", "instance_id", instance.InstanceID, "remote_addr", r.RemoteAddr)
					fmt.Fprintln(w, "Rotation sleep interrupted by client.")
					if okFlusher { flusher.Flush() }
					return
				}
			}
		}
		slog.Info("API: Staggered rotation completed for all healthy instances.")
		fmt.Fprintln(w, "Staggered rotation process completed.")
		if okFlusher { flusher.Flush() }
	}
}

// getInstanceFromRequest extracts the Tor instance based on path parameter.
func getInstanceFromRequest(r *http.Request, instances []*torinstance.Instance) (*torinstance.Instance, error) {
	instanceIDStr := r.PathValue("instanceid") 
	instanceID, err := strconv.Atoi(instanceIDStr) 
	if err != nil { 
		return nil, fmt.Errorf("invalid Tor instance ID in path (must be numeric): %s", instanceIDStr)
	}
	if instanceID < 1 || instanceID > len(instances) {
		return nil, fmt.Errorf("Tor instance ID out of range: %d (max: %d)", instanceID, len(instances))
	}
	return instances[instanceID-1], nil
}

// InstanceActionHandler creates a handler for a specific action on a Tor instance.
func InstanceActionHandler(instances []*torinstance.Instance, appCfg *config.AppConfig,
	actionFunc func(w http.ResponseWriter, r *http.Request, instance *torinstance.Instance, appCfg *config.AppConfig)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		instance, err := getInstanceFromRequest(r, instances)
		if err != nil {
			slog.Warn("API: Invalid instance ID in request.", "path", r.URL.Path, "error", err.Error(), "remote_addr", r.RemoteAddr)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		actionFunc(w, r, instance, appCfg)
	}
}

// Specific action functions to be wrapped by InstanceActionHandler

// HandleRotate handles requests to rotate a specific Tor instance's circuit.
// Renamed from handleRotate to be exported.
func HandleRotate(w http.ResponseWriter, r *http.Request, instance *torinstance.Instance, appCfg *config.AppConfig) {
	response, err := instance.SendTorCommand("SIGNAL NEWNYM", true)
	if err != nil {
		slog.Error("API: Failed to rotate instance.", "instance_id", instance.InstanceID, slog.Any("error", err))
		http.Error(w, "Failed to rotate instance "+strconv.Itoa(instance.InstanceID)+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	slog.Info("API: Instance rotated successfully.", "instance_id", instance.InstanceID, "response", firstNChars(response, 60))
	fmt.Fprintf(w, "Instance %d NEWNYM: %s", instance.InstanceID, response)
}

// HandleHealth handles requests to get the health status of a specific Tor instance.
// Renamed from handleHealth to be exported.
func HandleHealth(w http.ResponseWriter, r *http.Request, instance *torinstance.Instance, appCfg *config.AppConfig) {
	liveHealthy := instance.CheckHealth(r.Context())
	instance.Mu.Lock()
	cachedHealthy := instance.IsHealthy
	lastCheck := instance.LastHealthCheck
	instance.Mu.Unlock()

	respData := map[string]interface{}{
		"instance_id":               instance.InstanceID,
		"live_healthy_check_result": liveHealthy,
		"cached_is_healthy":         cachedHealthy,
		"last_health_check_at":      lastCheck.Format(time.RFC3339Nano),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respData)
}

// HandleStats handles requests to get statistics from a specific Tor instance.
// Renamed from handleStats to be exported.
func HandleStats(w http.ResponseWriter, r *http.Request, instance *torinstance.Instance, appCfg *config.AppConfig) {
	version, vErr := instance.SendTorCommand("GETINFO version", false)
	bootstrap, bErr := instance.SendTorCommand("GETINFO status/bootstrap-phase", false)
	trafficRead, trErr := instance.SendTorCommand("GETINFO traffic/read", false)
	trafficWritten, twErr := instance.SendTorCommand("GETINFO traffic/written", false)

	statsData := map[string]interface{}{
		"instance_id":              instance.InstanceID,
		"active_proxy_connections": instance.GetActiveProxyConnections(),
		"version":                  version, "version_error": fmtError(vErr),
		"bootstrap_status":         bootstrap, "bootstrap_error": fmtError(bErr),
		"traffic_read":             trafficRead, "traffic_read_error": fmtError(trErr),
		"traffic_written":          trafficWritten, "traffic_written_error": fmtError(twErr),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statsData)
}

// HandleIP handles requests to get the external IP address of a specific Tor instance.
// Renamed from handleIP to be exported.
func HandleIP(w http.ResponseWriter, r *http.Request, instance *torinstance.Instance, appCfg *config.AppConfig) {
	client := instance.GetHTTPClient()
	if client == nil {
		slog.Error("API: HTTP client not ready for instance.", "instance_id", instance.InstanceID)
		http.Error(w, "HTTP client for instance "+strconv.Itoa(instance.InstanceID)+" not ready", http.StatusServiceUnavailable)
		return
	}
	reqCtx, cancel := context.WithTimeout(r.Context(), appCfg.SocksTimeout*2+5*time.Second)
	defer cancel()

	httpReq, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, appCfg.IPCheckURL, nil)
	resp, err := client.Do(httpReq)
	if err != nil {
		slog.Error("API: Failed to get IP via instance.", "instance_id", instance.InstanceID, slog.Any("error", err), "target_url", appCfg.IPCheckURL)
		http.Error(w, "Failed to get IP via instance "+strconv.Itoa(instance.InstanceID)+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	body, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		slog.Error("API: Failed to read IP response body.", "instance_id", instance.InstanceID, slog.Any("error", errRead))
		http.Error(w, "Failed to read IP response body: "+errRead.Error(), http.StatusInternalServerError)
		return
	}
	
	var ipJsonResponse struct { IP string `json:"IP"`; IsTor bool `json:"IsTor"`}
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
			slog.Warn("API: IP response was not valid JSON or plain IP.", "instance_id", instance.InstanceID, "response_preview", firstNChars(trimmedBody, 50))
		}
	}

	if isJsonResponse {
		w.Header().Set("Content-Type", "application/json"); w.Write(body)
	} else if plainTextResponse != "" {
		w.Header().Set("Content-Type", "text/plain"); fmt.Fprint(w, plainTextResponse)
	} else {
		originalContentType := resp.Header.Get("Content-Type"); if originalContentType == "" { originalContentType = "text/plain" }
		w.Header().Set("Content-Type", originalContentType); w.Write(body)
	}
}

// HandleGetInstanceConfig handles requests to get configuration details of a specific Tor instance.
// Renamed from handleGetInstanceConfig to be exported.
func HandleGetInstanceConfig(w http.ResponseWriter, r *http.Request, instance *torinstance.Instance, appCfg *config.AppConfig) {
	instance.Mu.Lock()
	liveNodePolicies, errNP := instance.GetTorNodePolicies()
	if errNP != nil {
		slog.Error("API: Error fetching live node policies for config display.", "instance_id", instance.InstanceID, slog.Any("error", errNP))
	}
	cfgData := map[string]interface{}{
		"instance_id":              instance.InstanceID,
		"control_host":             instance.ControlHost,
		"backend_socks_host":       instance.BackendSocksHost,
		"backend_dns_host":         instance.BackendDNSHost,
		"is_healthy":               instance.IsHealthy,
		"last_health_check_at":     instance.LastHealthCheck.Format(time.RFC3339Nano),
		"external_ip":              instance.ExternalIP,
		"last_ip_check_at":         instance.LastIPCheck.Format(time.RFC3339Nano),
		"last_ip_change_at":        instance.LastIPChangeTime.Format(time.RFC3339Nano),
		"last_circuit_recreation_at": instance.LastCircuitRecreationTime.Format(time.RFC3339Nano),
		"last_diversity_rotate_at": instance.LastDiversityRotate.Format(time.RFC3339Nano),
		"active_proxy_connections": instance.GetActiveProxyConnections(),
		"auth_cookie_path":         instance.AuthCookiePath,
		"data_dir":                 instance.DataDir,
		"current_exitnode_policy":  liveNodePolicies["ExitNodes"],
		"current_entrynode_policy": liveNodePolicies["EntryNodes"],
		"current_excludenode_policy": liveNodePolicies["ExcludeNodes"],
		"current_geoip_file":       liveNodePolicies["GeoIPFile"],
		"current_geoip6_file":      liveNodePolicies["GeoIPv6File"],
	}
	instance.Mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfgData)
}

// HandleSetInstancePortConfig handles requests to set port configurations for a specific Tor instance.
// Renamed from handleSetInstancePortConfig to be exported.
func HandleSetInstancePortConfig(w http.ResponseWriter, r *http.Request, instance *torinstance.Instance, appCfg *config.AppConfig) {
	subAction := r.PathValue("porttype") 
	var reqBody struct { Address string `json:"address"`; Port int `json:"port"` }
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		slog.Warn("API: Invalid JSON for port config.", "instance_id", instance.InstanceID, "error", err.Error(), "remote_addr", r.RemoteAddr)
		http.Error(w, "Invalid JSON for port config: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if reqBody.Port < 0 || reqBody.Port > 65535 {
		slog.Warn("API: Invalid port number in request.", "instance_id", instance.InstanceID, "port", reqBody.Port)
		http.Error(w, "Invalid port number.", http.StatusBadRequest)
		return
	}
	newPortStr := strconv.Itoa(reqBody.Port)
	listenAddress := "127.0.0.1"
	if reqBody.Address != "" { listenAddress = reqBody.Address }

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
	default: 
		slog.Warn("API: Unknown port config type.", "instance_id", instance.InstanceID, "type", subAction)
		http.Error(w, "Unknown port config type: "+subAction, http.StatusBadRequest)
		return
	}
	
	slog.Info("API: Setting instance port.", "instance_id", instance.InstanceID, "config_key", torConfigKey, "address", fullAddressToSet)
	response, err := instance.SendTorCommand(fmt.Sprintf("SETCONF %s %s", torConfigKey, fullAddressToSet), false)
	if err != nil {
		slog.Error("API: Failed to set instance port.", "instance_id", instance.InstanceID, "config_key", torConfigKey, slog.Any("error", err))
		http.Error(w, fmt.Sprintf("Failed to set %s: %v", torConfigKey, err), http.StatusInternalServerError)
		return
	}
	if !strings.Contains(response, "250 OK") {
		slog.Error("API: Tor rejected port change.", "instance_id", instance.InstanceID, "config_key", torConfigKey, "response", response)
		http.Error(w, fmt.Sprintf("Tor rejected %s change: %s", torConfigKey, response), http.StatusInternalServerError)
		return
	}
	slog.Info("API: Instance port set successfully.", "instance_id", instance.InstanceID, "config_key", torConfigKey, "response", response)
	fmt.Fprintf(w, "Instance %d: %s set to %s. Tor response: %s\n", instance.InstanceID, torConfigKey, fullAddressToSet, response)
	instance.Mu.Lock()
	switch subAction {
	case "socksport": instance.BackendSocksHost = fullAddressToSet; go instance.ReinitializeHTTPClient()
	case "dnsport": instance.BackendDNSHost = fullAddressToSet
	case "controlport": instance.ControlHost = fullAddressToSet; instance.CloseControlConnUnlocked()
	}
	instance.Mu.Unlock()
	fmt.Fprintf(w, "API internal state for instance %d updated.\n", instance.InstanceID)
}

// HandleSetNodePolicy handles requests to set node policies for a specific Tor instance.
// Renamed from handleSetNodePolicy to be exported.
func HandleSetNodePolicy(w http.ResponseWriter, r *http.Request, instance *torinstance.Instance, appCfg *config.AppConfig) {
	var policyReq struct { PolicyType string `json:"policy_type"`; Nodes string `json:"nodes"`}
	if err := json.NewDecoder(r.Body).Decode(&policyReq); err != nil {
		slog.Warn("API: Invalid JSON for node policy.", "instance_id", instance.InstanceID, "error", err.Error(), "remote_addr", r.RemoteAddr)
		http.Error(w, "Invalid JSON for node policy: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if policyReq.PolicyType != "ExitNodes" && policyReq.PolicyType != "EntryNodes" && policyReq.PolicyType != "ExcludeNodes" {
		slog.Warn("API: Invalid node policy type.", "instance_id", instance.InstanceID, "policy_type", policyReq.PolicyType)
		http.Error(w, "Invalid policy_type.", http.StatusBadRequest)
		return
	}
	slog.Info("API: Setting node policy.", "instance_id", instance.InstanceID, "policy_type", policyReq.PolicyType, "nodes", policyReq.Nodes)
	response, err := instance.SetTorNodePolicy(policyReq.PolicyType, policyReq.Nodes)
	if err != nil {
		slog.Error("API: Error setting node policy.", "instance_id", instance.InstanceID, "policy_type", policyReq.PolicyType, "nodes", policyReq.Nodes, slog.Any("error", err), "tor_response", response)
		http.Error(w, fmt.Sprintf("Error setting Tor node policy: %v. Tor response: %s", err, response), http.StatusInternalServerError)
		return
	}
	slog.Info("API: Node policy set successfully.", "instance_id", instance.InstanceID, "policy_type", policyReq.PolicyType, "nodes", policyReq.Nodes, "tor_response", response)
	fmt.Fprintf(w, "Instance %d: Node policy %s set to '%s'. Tor response: %s", instance.InstanceID, policyReq.PolicyType, policyReq.Nodes, response)
}

// HandleGetPerformanceMetrics handles requests to get performance metrics for a specific Tor instance.
// Renamed from handleGetPerformanceMetrics to be exported.
func HandleGetPerformanceMetrics(w http.ResponseWriter, r *http.Request, instance *torinstance.Instance, appCfg *config.AppConfig) {
	metrics := instance.GetPerfMetrics()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}


func fmtError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
