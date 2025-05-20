package api

import (
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
	"context"


	"torgo/internal/config"
	"torgo/internal/torinstance"
)

func firstNChars(s string, n int) string {
    if len(s) > n {
        return s[:n]
    }
    return s
}

func rotateAllStaggeredHandler(w http.ResponseWriter, r *http.Request, instances []*torinstance.Instance, appCfg *config.AppConfig) {
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
	if okFlusher { flusher.Flush() }


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
		log.Println("API: No healthy instances to rotate."); fmt.Fprintln(w, "No healthy instances found to rotate."); return
	}

	log.Printf("API: Found %d healthy instances for staggered rotation.", len(healthyInstances))
	fmt.Fprintf(w, "Found %d healthy instances. Rotating with a %v delay between each...\n", len(healthyInstances), appCfg.RotationStaggerDelay)
	if okFlusher { flusher.Flush() }

	for i, instance := range healthyInstances {
		select {
		case <-r.Context().Done(): // Check if client disconnected
			log.Printf("API: Staggered rotation cancelled by client disconnect before instance %d.", instance.InstanceID)
			fmt.Fprintln(w, "Rotation cancelled by client."); return
		default:
		}
		log.Printf("API: Staggered rotation: Rotating instance %d (%s)", instance.InstanceID, instance.ControlHost)
		fmt.Fprintf(w, "Rotating instance %d (%s)...\n", instance.InstanceID, instance.ControlHost)
		if okFlusher { flusher.Flush() }

		response, err := instance.SendTorCommand("SIGNAL NEWNYM")
		if err != nil {
			log.Printf("API: Staggered rotation: Error rotating instance %d: %v", instance.InstanceID, err)
			fmt.Fprintf(w, "Error rotating instance %d: %v\n", instance.InstanceID, err)
		} else {
			log.Printf("API: Staggered rotation: Instance %d NEWNYM response: %s", instance.InstanceID, firstNChars(response, 60))
			fmt.Fprintf(w, "Instance %d NEWNYM response: %s\n", instance.InstanceID, firstNChars(response,60))
		}
		if okFlusher { flusher.Flush() }

		if i < len(healthyInstances)-1 { // Don't sleep after the last one
			log.Printf("API: Staggered rotation: Sleeping for %v before next instance.", appCfg.RotationStaggerDelay)
			select {
			case <-time.After(appCfg.RotationStaggerDelay):
			case <-r.Context().Done(): 
				log.Printf("API: Staggered rotation sleep interrupted by client disconnect for instance %d.", instance.InstanceID)
				fmt.Fprintln(w, "Rotation sleep interrupted by client."); return
			}
		}
	}
	log.Println("API: Staggered rotation completed for all healthy instances."); fmt.Fprintln(w, "Staggered rotation process completed.")
}

// MasterAPIRouter routes API calls to the appropriate handler.
func MasterAPIRouter(w http.ResponseWriter, r *http.Request, instances []*torinstance.Instance, appCfg *config.AppConfig) {
	path := r.URL.Path

	if path == "/api/v1/rotate-all-staggered" {
		if r.Method == http.MethodPost || r.Method == http.MethodGet {
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
	instance := instances[instanceID-1]
	action := parts[1]

	switch action {
	case "rotate":
		if r.Method != http.MethodPost && r.Method != http.MethodGet { http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed); return }
		response, err := instance.SendTorCommand("SIGNAL NEWNYM")
		if err != nil { http.Error(w, "Failed to rotate instance "+instanceIDStr+": "+err.Error(), http.StatusInternalServerError); return }
		fmt.Fprintf(w, "Instance %d NEWNYM: %s", instance.InstanceID, response)
	
	case "health":
		if r.Method != http.MethodGet { http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed); return }
		liveHealthy := instance.CheckHealth(r.Context())
		instance.Mu.Lock()
		cachedHealthy := instance.IsHealthy
		lastCheck := instance.LastHealthCheck
		instance.Mu.Unlock()
		
		respData := map[string]interface{}{
			"instance_id": instance.InstanceID,
			"live_healthy_check_result": liveHealthy,
			"cached_is_healthy": cachedHealthy,
			"last_health_check_at": lastCheck.Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(respData)

	case "stats":
		if r.Method != http.MethodGet { http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed); return }
		version, vErr := instance.SendTorCommand("GETINFO version")
		bootstrap, bErr := instance.SendTorCommand("GETINFO status/bootstrap-phase")
		trafficRead, trErr := instance.SendTorCommand("GETINFO traffic/read")
		trafficWritten, twErr := instance.SendTorCommand("GETINFO traffic/written")
		
		statsData := map[string]interface{}{
			"instance_id": instance.InstanceID,
			"version": version, "version_error": fmtError(vErr),
			"bootstrap_status": bootstrap, "bootstrap_error": fmtError(bErr),
			"traffic_read": trafficRead, "traffic_read_error": fmtError(trErr),
			"traffic_written": trafficWritten, "traffic_written_error": fmtError(twErr),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(statsData)

	case "ip":
		if r.Method != http.MethodGet { http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed); return }
		client := instance.GetHTTPClient()
		if client == nil { http.Error(w, "HTTP client for instance "+instanceIDStr+" not ready", http.StatusServiceUnavailable); return }
		
		reqCtx, cancel := context.WithTimeout(r.Context(), appCfg.SocksTimeout*2 + 5*time.Second)
		defer cancel()
		
		httpReq, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, appCfg.IPCheckURL, nil)
		resp, err := client.Do(httpReq)
		if err != nil { http.Error(w, "Failed to get IP via instance "+instanceIDStr+": "+err.Error(), http.StatusInternalServerError); return }
		defer resp.Body.Close()
		
		body, errRead := io.ReadAll(resp.Body)
		if errRead != nil {http.Error(w, "Failed to read IP response body from instance "+instanceIDStr+": "+errRead.Error(), http.StatusInternalServerError); return}

		var ipJsonResponse map[string]interface{}
		if json.Unmarshal(body, &ipJsonResponse) == nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write(body)
		} else {
			w.Header().Set("Content-Type", "text/plain")
			w.Write(body)
		}

	case "config":
		handleInstanceConfig(w, r, instance, parts, appCfg)
	
	default:
		http.NotFound(w, r)
	}
}

func handleInstanceConfig(w http.ResponseWriter, r *http.Request, instance *torinstance.Instance, pathParts []string, appCfg *config.AppConfig) {
	if len(pathParts) > 2 { 
		if r.Method != http.MethodPost { http.Error(w, "Method Not Allowed for setting config", http.StatusMethodNotAllowed); return }
		subAction := pathParts[2]
		
		var reqBody struct { 
			Address string `json:"address"`
			Port    int    `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			http.Error(w, "Invalid JSON request body: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if reqBody.Port < 0 || reqBody.Port > 65535 {
			http.Error(w, "Invalid port number. Must be between 0 and 65535.", http.StatusBadRequest)
			return
		}
		newPortStr := strconv.Itoa(reqBody.Port)
		listenAddress := "127.0.0.1" 
		if reqBody.Address != "" { 
			listenAddress = reqBody.Address
		}
		
		var torConfigKey string
		var fullAddressToSet string

		switch subAction {
		case "socksport":
			if reqBody.Port == 0 { http.Error(w, "SocksPort cannot be set to 0 (disabled).", http.StatusBadRequest); return }
			torConfigKey = "SocksPort"
			fullAddressToSet = net.JoinHostPort(listenAddress, newPortStr)
		case "dnsport":
			torConfigKey = "DNSPort"
			if reqBody.Port == 0 { fullAddressToSet = "0" } else { fullAddressToSet = net.JoinHostPort(listenAddress, newPortStr) }
		case "controlport":
			if reqBody.Port == 0 { http.Error(w, "ControlPort cannot be set to 0 (disabled).", http.StatusBadRequest); return }
			torConfigKey = "ControlPort"
			fullAddressToSet = net.JoinHostPort(listenAddress, newPortStr)
			fmt.Fprintln(w, "WARNING: Changing ControlPort is high-risk. API may lose contact if Tor fails to re-listen or API fails to reconnect.")
		default:
			http.Error(w, "Unknown config action: "+subAction, http.StatusBadRequest)
			return
		}

		log.Printf("API: Instance %d: Request to SETCONF %s=%s", instance.InstanceID, torConfigKey, fullAddressToSet)
		setConfCmd := fmt.Sprintf("SETCONF %s=%s", torConfigKey, fullAddressToSet)
		response, err := instance.SendTorCommand(setConfCmd)

		if err != nil {
			log.Printf("API: Instance %d: Error sending SETCONF %s: %v", instance.InstanceID, torConfigKey, err)
			http.Error(w, fmt.Sprintf("Failed to set %s in Tor: %v", torConfigKey, err), http.StatusInternalServerError)
			return
		}
		if !strings.Contains(response, "250 OK") {
			log.Printf("API: Instance %d: Tor rejected SETCONF %s. Response: %s", instance.InstanceID, torConfigKey, response)
			http.Error(w, fmt.Sprintf("Tor rejected %s change. Response: %s", torConfigKey, response), http.StatusInternalServerError)
			return
		}
		
		log.Printf("API: Instance %d: Successfully sent SETCONF %s. Response: %s", instance.InstanceID, torConfigKey, response)
		fmt.Fprintf(w, "Instance %d: %s set to %s for current Tor session. Tor response: %s\n", instance.InstanceID, torConfigKey, fullAddressToSet, response)

		// Update internal state
		switch subAction {
		case "socksport":
			instance.Mu.Lock()
			instance.BackendSocksHost = fullAddressToSet 
			instance.Mu.Unlock()
			// Call the exported method which handles its own locking
			instance.ReinitializeHTTPClient()
		case "dnsport":
			instance.Mu.Lock()
			instance.BackendDNSHost = fullAddressToSet
			instance.Mu.Unlock()
		case "controlport":
			instance.Mu.Lock()
			oldControlHost := instance.ControlHost
			instance.ControlHost = fullAddressToSet
			instance.CloseControlConnUnlocked() 
			log.Printf("Instance %d: Internal ControlHost updated to %s. Old was %s. Will attempt reconnect on next command.", instance.InstanceID, instance.ControlHost, oldControlHost)
			instance.Mu.Unlock()
		}
		fmt.Fprintf(w, "API internal state for instance %d for %s updated.\n", instance.InstanceID, subAction)

	} else { 
		if r.Method != http.MethodGet { http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed); return }
		instance.Mu.Lock()
		cfgData := map[string]interface{}{
			"instance_id":        instance.InstanceID,
			"control_host":       instance.ControlHost,
			"backend_socks_host": instance.BackendSocksHost,
			"backend_dns_host":   instance.BackendDNSHost,
			"is_healthy":         instance.IsHealthy,
			"last_health_check":  instance.LastHealthCheck.Format(time.RFC3339),
			"auth_cookie_path":   instance.AuthCookiePath,
			"data_dir":           instance.DataDir,
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
