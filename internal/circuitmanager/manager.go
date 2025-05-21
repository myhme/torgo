package circuitmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog" // Import slog
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"torgo/internal/config"
	"torgo/internal/torinstance"
)

var (
	circuitRotationInProgress int32
)

// CircuitManager orchestrates circuit rotation and performance testing.
type CircuitManager struct {
	appCfg    *config.AppConfig
	instances []*torinstance.Instance
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// New creates a new CircuitManager.
func New(ctx context.Context, appCfg *config.AppConfig, instances []*torinstance.Instance) *CircuitManager {
	managerCtx, managerCancel := context.WithCancel(ctx)
	return &CircuitManager{
		appCfg:    appCfg,
		instances: instances,
		ctx:       managerCtx,
		cancel:    managerCancel,
	}
}

// Start begins the monitoring loops for circuit management and performance testing.
func (cm *CircuitManager) Start() {
	if !cm.appCfg.CircuitManagerEnabled && !cm.appCfg.PerfTestEnabled {
		slog.Info("CircuitManager & PerfTester: Both disabled by configuration. Manager not starting.")
		return
	}

	slog.Info("CircuitManager: Starting...")
	cm.wg.Add(1)
	go cm.rotationLoop()

	if cm.appCfg.PerfTestEnabled {
		cm.wg.Add(1)
		go cm.performanceTestLoop()
	}
}

// Stop signals the manager to stop and waits for its goroutines to finish.
func (cm *CircuitManager) Stop() {
	slog.Info("CircuitManager: Stopping...")
	cm.cancel()
	cm.wg.Wait()
	slog.Info("CircuitManager: Stopped.")
}

// rotationLoop periodically checks instances for circuit rotation needs (age, IP diversity).
func (cm *CircuitManager) rotationLoop() {
	defer cm.wg.Done()
	if !cm.appCfg.CircuitManagerEnabled {
		slog.Info("CircuitManager: Rotation loop disabled by configuration.")
		return
	}

	// Determine a sensible check interval, e.g., 1/5th of the shortest relevant period, or a minimum.
	checkInterval := cm.appCfg.CircuitMaxAge / 5
	if cm.appCfg.IPDiversityCheckEnabled && cm.appCfg.IPDiversitySubnetCheckInterval > 0 && cm.appCfg.IPDiversitySubnetCheckInterval/5 < checkInterval {
		checkInterval = cm.appCfg.IPDiversitySubnetCheckInterval / 5
	}
	if checkInterval < 1*time.Minute { // Minimum check interval
		checkInterval = 1 * time.Minute
	}
	if checkInterval == 0 && cm.appCfg.CircuitMaxAge > 0 { // if only max age is set
	    checkInterval = cm.appCfg.CircuitMaxAge / 5
		if checkInterval < 1*time.Minute { checkInterval = 1*time.Minute }
	} else if checkInterval == 0 { // if no rotation criteria are meaningfully enabled with timing
		slog.Info("CircuitManager: Rotation loop effectively disabled as no timed rotation criteria are set.")
		return
	}


	slog.Info("CircuitManager: Rotation check interval.", "interval", checkInterval)
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	// Initial IP diversity check run if enabled
	if cm.appCfg.IPDiversityCheckEnabled && len(cm.instances) >= cm.appCfg.IPDiversityMinInstances {
		slog.Info("CircuitManager: Performing initial IP diversity check...")
		cm.checkForIPDiversityAndRotate()
	}


	for {
		select {
		case <-ticker.C:
			cm.processEligibleInstanceForRotation()
			// IP diversity check might have its own rhythm or be part of the main check
			if cm.appCfg.IPDiversityCheckEnabled && cm.appCfg.IPDiversitySubnetCheckInterval > 0 && time.Since(lastIPDiversityGlobalCheckTime) > cm.appCfg.IPDiversitySubnetCheckInterval {
				cm.checkForIPDiversityAndRotate()
			}
		case <-cm.ctx.Done():
			slog.Info("CircuitManager: Rotation loop stopping due to context cancellation.")
			return
		}
	}
}

var lastIPDiversityGlobalCheckTime time.Time

// processEligibleInstanceForRotation finds one instance that needs rotation (due to age or other future criteria)
// and triggers its rotation, respecting the global stagger.
func (cm *CircuitManager) processEligibleInstanceForRotation() {
	if !cm.appCfg.CircuitManagerEnabled { return }
	if !atomic.CompareAndSwapInt32(&circuitRotationInProgress, 0, 1) {
		slog.Debug("CircuitManager: A managed rotation is already in progress or respecting stagger. Skipping this cycle.")
		return
	}
	// Successfully acquired the "lock"

	var instanceToRotate *torinstance.Instance
	var oldestRecreationTime time.Time
	var rotationReason string
	now := time.Now()

	// Check for age-based rotation
	if cm.appCfg.CircuitMaxAge > 0 {
		for _, inst := range cm.instances {
			inst.Mu.Lock()
			isHealthy := inst.IsHealthy
			lastRecTime := inst.LastCircuitRecreationTime
			inst.Mu.Unlock()
			if !isHealthy { continue }
			circuitAge := now.Sub(lastRecTime)
			if lastRecTime.IsZero() { // Never rotated, consider it infinitely old for rotation purposes
				circuitAge = cm.appCfg.CircuitMaxAge + 1*time.Second // Ensure it's older
			}


			if circuitAge > cm.appCfg.CircuitMaxAge {
				if instanceToRotate == nil || lastRecTime.Before(oldestRecreationTime) || (lastRecTime.IsZero() && !oldestRecreationTime.IsZero()) {
					instanceToRotate = inst
					oldestRecreationTime = lastRecTime
					rotationReason = fmt.Sprintf("circuit age %v > max %v", circuitAge.Round(time.Second), cm.appCfg.CircuitMaxAge)
				}
			}
		}
	}


	if instanceToRotate != nil {
		slog.Info("CircuitManager: Instance selected for rotation.", 
			"instance_id", instanceToRotate.InstanceID, 
			"reason", rotationReason, 
			"last_recreation", oldestRecreationTime.Format(time.RFC3339))
		go cm.rotateInstanceWithStagger(instanceToRotate, rotationReason)
	} else {
		atomic.StoreInt32(&circuitRotationInProgress, 0) // No instance found, release lock
	}
}

// checkForIPDiversityAndRotate checks for IP similarity and rotates one instance if needed.
// This is a more focused check for IP diversity, potentially run on its own schedule.
func (cm *CircuitManager) checkForIPDiversityAndRotate() {
	if !cm.appCfg.IPDiversityCheckEnabled || len(cm.instances) < cm.appCfg.IPDiversityMinInstances {
		return
	}
	if !atomic.CompareAndSwapInt32(&circuitRotationInProgress, 0, 1) {
		slog.Debug("CircuitManager: IP Diversity check skipped, a rotation is already in progress or respecting stagger.")
		return
	}
	lastIPDiversityGlobalCheckTime = time.Now()
	slog.Debug("CircuitManager: Running IP diversity check...")

	currentIPs := make(map[int]string)
	healthyInstancesForCheck := make([]*torinstance.Instance, 0)
	now := time.Now()

	for _, instance := range cm.instances {
		instance.Mu.Lock()
		isHealthy := instance.IsHealthy
		lastIPCheck := instance.LastIPCheck
		currentExtIP := instance.ExternalIP
		instance.Mu.Unlock()

		if !isHealthy { continue }
		healthyInstancesForCheck = append(healthyInstancesForCheck, instance)

		ipStaleDuration := cm.appCfg.IPDiversitySubnetCheckInterval / 2
		if ipStaleDuration < 1*time.Minute { ipStaleDuration = 1*time.Minute}
		if cm.appCfg.IPDiversitySubnetCheckInterval == 0 { ipStaleDuration = 5 * time.Minute } // Default if interval is 0


		if currentExtIP == "" || now.Sub(lastIPCheck) > ipStaleDuration {
			cm.fetchAndUpdateInstanceIP(instance) // Fetches and sets IP inside instance
			instance.Mu.Lock() // Re-lock to get potentially updated IP
			currentExtIP = instance.ExternalIP
			instance.Mu.Unlock()
		}
		if currentExtIP != "" { currentIPs[instance.InstanceID] = currentExtIP }
	}

	if len(currentIPs) < cm.appCfg.IPDiversityMinInstances {
		slog.Debug("CircuitManager: Not enough IPs fetched for diversity check.", "fetched_count", len(currentIPs), "min_required", cm.appCfg.IPDiversityMinInstances)
		atomic.StoreInt32(&circuitRotationInProgress, 0) // Release lock
		return
	}

	subnets := make(map[string][]*torinstance.Instance)
	for instanceID, ipStr := range currentIPs {
		parsedIP := net.ParseIP(ipStr)
		if parsedIP == nil || parsedIP.To4() == nil { continue }
		subnetPrefix := fmt.Sprintf("%d.%d.%d", parsedIP.To4()[0], parsedIP.To4()[1], parsedIP.To4()[2])
		var instPtr *torinstance.Instance
		for _, inst := range healthyInstancesForCheck {
			if inst.InstanceID == instanceID { instPtr = inst; break }
		}
		if instPtr != nil { subnets[subnetPrefix] = append(subnets[subnetPrefix], instPtr) }
	}

	var instanceToRotateIPDiversity *torinstance.Instance
	var oldestDiversityRotateTime time.Time
	var qualifyingSubnet string

	for subnet, instancesInSubnet := range subnets {
		if len(instancesInSubnet) >= 2 { // Found a subnet with multiple instances
			for _, inst := range instancesInSubnet {
				inst.Mu.Lock()
				lastRot := inst.LastDiversityRotate
				inst.Mu.Unlock()
				if now.Sub(lastRot) > cm.appCfg.IPDiversityRotationCooldown { // Check cooldown for this specific instance
					if instanceToRotateIPDiversity == nil || lastRot.Before(oldestDiversityRotateTime) {
						instanceToRotateIPDiversity = inst
						oldestDiversityRotateTime = lastRot
						qualifyingSubnet = subnet
					}
				}
			}
		}
	}

	if instanceToRotateIPDiversity != nil {
		reason := fmt.Sprintf("IP diversity in subnet %s.0/24", qualifyingSubnet)
		slog.Info("CircuitManager: Instance selected for IP diversity rotation.", "instance_id", instanceToRotateIPDiversity.InstanceID, "reason", reason)
		go cm.rotateInstanceWithStagger(instanceToRotateIPDiversity, reason)
		// rotateInstanceWithStagger will release the circuitRotationInProgress lock
	} else {
		slog.Debug("CircuitManager: No instance eligible for IP diversity rotation at this time.")
		atomic.StoreInt32(&circuitRotationInProgress, 0) // No IP diversity rotation needed, release lock
	}
}


func (cm *CircuitManager) rotateInstanceWithStagger(instance *torinstance.Instance, reason string) {
	// The circuitRotationInProgress lock is already held by the caller.
	// This function will release it after the stagger.
	defer atomic.StoreInt32(&circuitRotationInProgress, 0)

	slog.Info("CircuitManager: Rotating instance, sending NEWNYM.", "instance_id", instance.InstanceID, "reason", reason)
	// true to update LastCircuitRecreationTime
	_, err := instance.SendTorCommand("SIGNAL NEWNYM", true)

	if err != nil {
		slog.Error("CircuitManager: Error rotating instance.", "instance_id", instance.InstanceID, slog.Any("error", err))
	} else {
		slog.Info("CircuitManager: Successfully sent NEWNYM to instance.", "instance_id", instance.InstanceID)
		instance.Mu.Lock()
		if strings.Contains(reason, "IP diversity") {
			instance.LastDiversityRotate = time.Now()
		}
		instance.Mu.Unlock()
	}

	if cm.appCfg.CircuitRotationStagger > 0 {
		slog.Debug("CircuitManager: Staggering after rotation.", "instance_id", instance.InstanceID, "delay", cm.appCfg.CircuitRotationStagger)
		select {
		case <-time.After(cm.appCfg.CircuitRotationStagger):
		case <-cm.ctx.Done():
			slog.Info("CircuitManager: Stagger delay interrupted by shutdown.", "instance_id", instance.InstanceID)
			return
		}
	}
}


// --- Performance Testing ---

func (cm *CircuitManager) performanceTestLoop() {
	defer cm.wg.Done()
	if !cm.appCfg.PerfTestEnabled {
		slog.Info("CircuitManager: Performance test loop disabled.")
		return
	}
	slog.Info("CircuitManager: Performance test loop started.", "interval", cm.appCfg.PerfTestInterval)
	
	if cm.appCfg.PerfTestInterval <= 0 {
		slog.Warn("CircuitManager: Performance test interval is not positive, loop will not run effectively.")
		return
	}
	ticker := time.NewTicker(cm.appCfg.PerfTestInterval)
	defer ticker.Stop()

	cm.runAllPerformanceTests() // Initial run

	for {
		select {
		case <-ticker.C:
			cm.runAllPerformanceTests()
		case <-cm.ctx.Done():
			slog.Info("CircuitManager: Performance test loop stopping.")
			return
		}
	}
}

func (cm *CircuitManager) runAllPerformanceTests() {
	slog.Debug("CircuitManager: Running performance tests for all healthy instances...")
	for _, instance := range cm.instances {
		instance.Mu.Lock()
		isHealthy := instance.IsHealthy
		instance.Mu.Unlock()
		if isHealthy {
			// Run tests for one instance in a goroutine to parallelize slightly,
			// but be mindful of not overwhelming the network or test servers.
			// A semaphore could be used here if too many instances.
			go cm.performInstanceTests(instance)
		}
	}
}

func (cm *CircuitManager) performInstanceTests(instance *torinstance.Instance) {
	httpClient := instance.GetHTTPClient()
	if httpClient == nil { // Should not happen if healthy
		slog.Warn("CircuitManager: HTTP client not available for perf test.", "instance_id", instance.InstanceID)
		return
	}

	// Latency tests
	for alias, targetURL := range cm.appCfg.LatencyTestTargets {
		startTime := time.Now()
		// Use HEAD request for latency to minimize data transfer
		req, _ := http.NewRequestWithContext(cm.ctx, http.MethodHead, targetURL, nil)
		resp, err := httpClient.Do(req)
		latency := time.Since(startTime)
		failed := false
		if err != nil {
			slog.Warn("CircuitManager: Latency test FAILED (request error).", "instance_id", instance.InstanceID, "target_alias", alias, "url", targetURL, slog.Any("error", err))
			failed = true
		} else {
			resp.Body.Close() // Important to close body even for HEAD
			if resp.StatusCode >= 400 { // Consider HTTP errors as failures too
				slog.Warn("CircuitManager: Latency test FAILED (HTTP status).", "instance_id", instance.InstanceID, "target_alias", alias, "url", targetURL, "status_code", resp.StatusCode)
				failed = true
			} else {
				slog.Debug("CircuitManager: Latency test success.", "instance_id", instance.InstanceID, "target_alias", alias, "url", targetURL, "latency", latency.Round(time.Millisecond))
			}
		}
		instance.UpdatePerfMetric(alias+"_latency", latency.Milliseconds(), 0, failed)
	}

	// Speed test (light)
	if cm.appCfg.SpeedTestTargetURL != "" && cm.appCfg.SpeedTestTargetBytes > 0 {
		targetURL := cm.appCfg.SpeedTestTargetURL
		if strings.HasSuffix(targetURL, "=") { // For Cloudflare like URL
			targetURL = fmt.Sprintf("%s%d", cm.appCfg.SpeedTestTargetURL, cm.appCfg.SpeedTestTargetBytes)
		}
		
		startTime := time.Now()
		req, _ := http.NewRequestWithContext(cm.ctx, http.MethodGet, targetURL, nil)
		resp, err := httpClient.Do(req)
		var bytesRead int64 = 0
		if err == nil {
			bytesRead, _ = io.Copy(io.Discard, resp.Body) // Read and discard
			resp.Body.Close()
		}
		duration := time.Since(startTime)
		
		failed := false
		var speedKBps float64 = 0
		if err != nil {
			slog.Warn("CircuitManager: Speed test FAILED (request error).", "instance_id", instance.InstanceID, "url", targetURL, slog.Any("error", err))
			failed = true
		} else if resp.StatusCode >= 400 {
			slog.Warn("CircuitManager: Speed test FAILED (HTTP status).", "instance_id", instance.InstanceID, "url", targetURL, "status_code", resp.StatusCode)
			failed = true
		} else if duration.Seconds() > 0 && bytesRead > 0 {
			speedBytesPerSec := float64(bytesRead) / duration.Seconds()
			speedKBps = speedBytesPerSec / 1024
			slog.Debug("CircuitManager: Speed test success.", "instance_id", instance.InstanceID, "url", targetURL, "speed_kbps", fmt.Sprintf("%.2f", speedKBps), "bytes_read", bytesRead, "duration", duration.Round(time.Millisecond))
		} else if bytesRead == 0 && err == nil {
			slog.Warn("CircuitManager: Speed test: 0 bytes read.", "instance_id", instance.InstanceID, "url", targetURL)
			failed = true // Or handle as very slow / inconclusive
		}
		instance.UpdatePerfMetric("default_speed", 0, speedKBps, failed)
	}
}


// Helper to fetch and update an instance's IP, used by IP diversity check
func (cm *CircuitManager) fetchAndUpdateInstanceIP(instance *torinstance.Instance) {
	httpClient := instance.GetHTTPClient()
	if httpClient == nil {
		slog.Warn("CircuitManager: HTTP client not available for IP fetch.", "instance_id", instance.InstanceID)
		return
	}
	reqCtx, cancel := context.WithTimeout(cm.ctx, cm.appCfg.SocksTimeout*2)
	defer cancel()
	httpReq, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, cm.appCfg.IPCheckURL, nil)
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		slog.Warn("CircuitManager: Error fetching IP for diversity check.", "instance_id", instance.InstanceID, slog.Any("error", err))
		return
	}
	defer resp.Body.Close()
	body, errRead := io.ReadAll(resp.Body)
	if errRead != nil {
		slog.Warn("CircuitManager: Error reading IP response body for diversity check.", "instance_id", instance.InstanceID, slog.Any("error", errRead))
		return
	}
	var ipJsonResponse struct{ IP string `json:"IP"` }
	if errJson := json.Unmarshal(body, &ipJsonResponse); errJson == nil && ipJsonResponse.IP != "" {
		instance.SetExternalIP(ipJsonResponse.IP)
	} else {
		trimmedBody := strings.TrimSpace(string(body))
		if net.ParseIP(trimmedBody) != nil {
			instance.SetExternalIP(trimmedBody)
		} else {
			// Use the exported function from torinstance package
			slog.Debug("CircuitManager: IP response not valid JSON or plain IP.", "instance_id", instance.InstanceID, "response_preview", torinstance.FirstNChars(trimmedBody, 30))
		}
	}
}
