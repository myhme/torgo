package torinstance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
	"torgo/internal/config"
)

// PerformanceMetrics stores results from latency and speed tests.
type PerformanceMetrics struct {
	LatencyMilliSeconds int64     `json:"latency_ms"`       // Round-trip time in milliseconds
	DownloadSpeedKBps   float64   `json:"download_speed_kbps"` // Kilobytes per second
	LastTestTime        time.Time `json:"last_test_time"`
	TestTarget          string    `json:"test_target"` // Alias like "cloudflare", "google"
	TestFailures        int       `json:"test_failures"` // Consecutive failures for this target
	IsStale             bool      `json:"is_stale"`      // If data is too old
}

// maskIP partially hides an IP address for logging.
func maskIP(ipAddress string) string {
	// ... (same as before)
	if ipAddress == "" {
		return "empty"
	}
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return "invalid_ip_format"
	}

	if ip.To4() != nil {
		parts := strings.Split(ipAddress, ".")
		if len(parts) == 4 {
			return fmt.Sprintf("%s.%s.x.x", parts[0], parts[1])
		}
	} else { // IPv6
		parts := strings.Split(ipAddress, ":")
		if len(parts) > 2 {
			maskedParts := []string{}
			for i, part := range parts {
				if i < 2 {
					maskedParts = append(maskedParts, part)
				} else {
					if len(maskedParts) < 4 {
						maskedParts = append(maskedParts, "x")
					}
				}
			}
			finalParts := []string{}
			for i := 0; i < len(parts) && i < 4; i++ {
				if i < len(maskedParts) {
					finalParts = append(finalParts, maskedParts[i])
				} else {
					finalParts = append(finalParts, "x")
				}
			}
			return strings.Join(finalParts, ":")
		}
	}
	return "ip_mask_failed"
}

// Instance represents a single backend Tor process and its state.
type Instance struct {
	InstanceID       int
	ControlHost      string
	BackendSocksHost string
	BackendDNSHost   string
	AuthCookiePath   string
	DataDir          string

	Mu                  sync.Mutex // Protects all fields below not handled by atomic ops
	httpClient          *http.Client
	activeControlConn   net.Conn
	controlCookieHex    string
	IsHealthy           bool
	LastHealthCheck     time.Time
	ConsecutiveFailures int // Health check failures

	// IP Diversity Management
	ExternalIP          string
	LastIPCheck         time.Time // When ExternalIP was last successfully fetched
	LastIPChangeTime    time.Time // When ExternalIP value actually changed
	LastDiversityRotate time.Time // Cooldown for IP diversity based rotation

	// Circuit Age Management
	LastCircuitRecreationTime time.Time // When NEWNYM was last successfully sent (for any reason)

	// Load Balancing
	ActiveProxyConnections int32 // Atomically accessed

	// Performance Metrics
	PerfMetrics map[string]*PerformanceMetrics // Key: target alias (e.g., "google", "cloudflare_latency", "cloudflare_speed")

	// Tor Exit Node Configuration
	CurrentExitNodePolicy   string // Stores current "ExitNodes {US},{DE}" or "ExcludeNodes {RU}"
	CurrentEntryNodePolicy  string
	CurrentGeoIPFile        string
	CurrentGeoIPv6File      string


	appConfig *config.AppConfig
}

// New creates a new Tor instance configuration.
func New(id int, appCfg *config.AppConfig) *Instance {
	controlPort := appCfg.ControlBasePort + id
	socksPort := appCfg.SocksBasePort + id
	dnsPort := appCfg.DNSBasePort + id
	initialTime := time.Time{}

	ti := &Instance{
		InstanceID:                id,
		ControlHost:               fmt.Sprintf("127.0.0.1:%d", controlPort),
		BackendSocksHost:          fmt.Sprintf("127.0.0.1:%d", socksPort),
		BackendDNSHost:            fmt.Sprintf("127.0.0.1:%d", dnsPort),
		AuthCookiePath:            fmt.Sprintf("/var/lib/tor/instance%d/control_auth_cookie", id),
		DataDir:                   fmt.Sprintf("/var/lib/tor/instance%d", id),
		IsHealthy:                 false,
		LastCircuitRecreationTime: initialTime, // Will be set by first successful NEWNYM
		LastIPChangeTime:          initialTime,
		LastDiversityRotate:       initialTime,
		ActiveProxyConnections:    0,
		PerfMetrics:               make(map[string]*PerformanceMetrics),
		appConfig:                 appCfg,
	}
	ti.Mu.Lock()
	ti.initializeHTTPClientUnlocked()
	// Initialize PerfMetrics map for configured targets
	for alias := range appCfg.LatencyTestTargets {
		ti.PerfMetrics[alias+"_latency"] = &PerformanceMetrics{TestTarget: alias + "_latency"}
	}
	if appCfg.SpeedTestTargetURL != "" && appCfg.SpeedTestTargetBytes > 0 {
		ti.PerfMetrics["default_speed"] = &PerformanceMetrics{TestTarget: "default_speed"}
	}
	ti.Mu.Unlock()
	return ti
}

// UpdatePerfMetric updates or adds a performance metric for a given target.
func (ti *Instance) UpdatePerfMetric(targetAlias string, latencyMs int64, speedKBps float64, testFailed bool) {
	ti.Mu.Lock()
	defer ti.Mu.Unlock()

	metric, ok := ti.PerfMetrics[targetAlias]
	if !ok {
		metric = &PerformanceMetrics{TestTarget: targetAlias}
		ti.PerfMetrics[targetAlias] = metric
	}

	metric.LastTestTime = time.Now()
	metric.IsStale = false // Data just updated

	if testFailed {
		metric.TestFailures++
		// Keep old values on failure, or clear them? For now, keep.
		// metric.LatencyMilliSeconds = -1 // Indicate failure
		// metric.DownloadSpeedKBps = -1
	} else {
		metric.LatencyMilliSeconds = latencyMs
		metric.DownloadSpeedKBps = speedKBps
		metric.TestFailures = 0
	}
}

// GetPerfMetrics returns a copy of the performance metrics.
func (ti *Instance) GetPerfMetrics() map[string]PerformanceMetrics {
	ti.Mu.Lock()
	defer ti.Mu.Unlock()

	metricsCopy := make(map[string]PerformanceMetrics)
	staleDuration := ti.appConfig.PerfTestInterval + (ti.appConfig.PerfTestInterval / 2) // e.g., 1.5 * interval

	for key, metricPtr := range ti.PerfMetrics {
		copiedMetric := *metricPtr // Dereference to copy the struct
		if !copiedMetric.LastTestTime.IsZero() && time.Since(copiedMetric.LastTestTime) > staleDuration {
			copiedMetric.IsStale = true
		}
		metricsCopy[key] = copiedMetric
	}
	return metricsCopy
}


// IncrementActiveProxyConnections ... (same as before)
func (ti *Instance) IncrementActiveProxyConnections() {
	atomic.AddInt32(&ti.ActiveProxyConnections, 1)
}

// DecrementActiveProxyConnections ... (same as before)
func (ti *Instance) DecrementActiveProxyConnections() {
	atomic.AddInt32(&ti.ActiveProxyConnections, -1)
}

// GetActiveProxyConnections ... (same as before)
func (ti *Instance) GetActiveProxyConnections() int32 {
	return atomic.LoadInt32(&ti.ActiveProxyConnections)
}


func (ti *Instance) loadAndCacheControlCookieUnlocked(forceReload bool) error {
	// ... (same as before)
	if ti.controlCookieHex != "" && !forceReload {
		return nil
	}
	cookieBytes, err := os.ReadFile(ti.AuthCookiePath)
	if err != nil {
		ti.controlCookieHex = ""
		return fmt.Errorf("instance %d: failed to read cookie %s: %w", ti.InstanceID, ti.AuthCookiePath, err)
	}
	ti.controlCookieHex = hex.EncodeToString(cookieBytes)
	return nil
}

func (ti *Instance) connectToTorControlUnlocked() (net.Conn, *bufio.Reader, error) {
	// ... (same as before)
	if err := ti.loadAndCacheControlCookieUnlocked(false); err != nil {
		return nil, nil, fmt.Errorf("instance %d: pre-connect cookie load failed: %w", ti.InstanceID, err)
	}
	if ti.controlCookieHex == "" {
		return nil, nil, fmt.Errorf("instance %d: control cookie is empty after load attempt", ti.InstanceID)
	}

	conn, err := net.DialTimeout("tcp", ti.ControlHost, 5*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("instance %d: failed to connect to control port %s: %w", ti.InstanceID, ti.ControlHost, err)
	}

	authCmd := fmt.Sprintf("AUTHENTICATE %s\r\n", ti.controlCookieHex)
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write([]byte(authCmd))
	conn.SetWriteDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("instance %d: failed to send AUTHENTICATE command: %w", ti.InstanceID, err)
	}

	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	statusLine, err := reader.ReadString('\n')
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("instance %d: failed to read authentication response: %w", ti.InstanceID, err)
	}

	trimmedStatus := strings.TrimSpace(statusLine)
	if !strings.HasPrefix(trimmedStatus, "250 OK") {
		conn.Close()
		if strings.HasPrefix(trimmedStatus, "515") {
			log.Printf("Instance %d: Control port authentication failed (515). Invalidating cached cookie. Will retry reading on next attempt. Tor msg: %s", ti.InstanceID, trimmedStatus)
			ti.controlCookieHex = ""
		}
		return nil, nil, fmt.Errorf("instance %d: tor control port authentication failed: %s", ti.InstanceID, trimmedStatus)
	}
	ti.activeControlConn = conn
	return conn, reader, nil
}

func (ti *Instance) CloseControlConnUnlocked() {
	// ... (same as before)
	if ti.activeControlConn != nil {
		ti.activeControlConn.Close()
		ti.activeControlConn = nil
	}
}

// SendTorCommand sends a command to the Tor control port.
// It now updates LastCircuitRecreationTime internally if the command is SIGNAL NEWNYM and successful.
func (ti *Instance) SendTorCommand(command string, updateCircuitTimeOnNewnym bool) (string, error) {
	ti.Mu.Lock()
	defer ti.Mu.Unlock()

	var conn net.Conn
	var reader *bufio.Reader
	var err error

	for attempt := 0; attempt < 2; attempt++ {
		if ti.activeControlConn != nil {
			conn = ti.activeControlConn
			reader = bufio.NewReader(conn)
		} else {
			conn, reader, err = ti.connectToTorControlUnlocked()
			if err != nil {
				if attempt == 0 {
					log.Printf("Instance %d SendTorCommand: connection attempt %d failed: %v. Retrying...", ti.InstanceID, attempt+1, err)
					ti.CloseControlConnUnlocked()
					if strings.Contains(err.Error(), "authentication failed") {
						ti.controlCookieHex = "" // Force reload of cookie
					}
					continue
				}
				return "", fmt.Errorf("instance %d SendTorCommand: connection phase failed after retries: %w", ti.InstanceID, err)
			}
		}

		conn.SetWriteDeadline(time.Now().Add(ti.appConfig.SocksTimeout))
		if _, errWrite := conn.Write([]byte(command + "\r\n")); errWrite != nil {
			conn.SetWriteDeadline(time.Time{})
			ti.CloseControlConnUnlocked()
			log.Printf("Instance %d: Write failed for command '%s' (%v), connection closed. Attempt %d.", ti.InstanceID, command, errWrite, attempt+1)
			if attempt == 0 { continue }
			return "", fmt.Errorf("instance %d: write failed for command '%s': %w", ti.InstanceID, command, errWrite)
		}
		conn.SetWriteDeadline(time.Time{})

		var responseBuffer bytes.Buffer
		isMultiLine := strings.HasPrefix(command, "GETINFO") || strings.HasPrefix(command, "GETCONF")
		readDeadlineDuration := 10 * time.Second
		if isMultiLine { readDeadlineDuration = 20 * time.Second }

		conn.SetReadDeadline(time.Now().Add(readDeadlineDuration))

		for {
			line, errRead := reader.ReadString('\n')
			if errRead != nil {
				conn.SetReadDeadline(time.Time{})
				ti.CloseControlConnUnlocked()
				responseStrPartial := strings.TrimSpace(responseBuffer.String())
				// Handle EOF correctly, especially for NEWNYM
				if errRead == io.EOF && responseBuffer.Len() > 0 {
					if updateCircuitTimeOnNewnym && strings.HasPrefix(command, "SIGNAL NEWNYM") && strings.HasPrefix(responseStrPartial, "250 OK") {
						ti.LastCircuitRecreationTime = time.Now()
						log.Printf("Instance %d: LastCircuitRecreationTime updated to %v (NEWNYM, EOF path)", ti.InstanceID, ti.LastCircuitRecreationTime)
					}
					return responseStrPartial, nil // Return what we have on EOF
				}
				// If not EOF or if buffer is empty on EOF, and it's the first attempt, retry
				if attempt == 0 { break } // Break inner loop to retry connection
				return responseBuffer.String(), fmt.Errorf("instance %d: failed to read full response for '%s': %w. Partial: '%s'", ti.InstanceID, command, errRead, responseBuffer.String())
			}
			responseBuffer.WriteString(line)
			trimmedLine := strings.TrimSpace(line)

			// Check for final line of response
			// For multi-line, it's "250 OK" or "250-..." followed by "250 OK"
			// For single-line, it's "250 ..." (not "250-") or any error code "5xx"
			isFinalOK := strings.HasPrefix(trimmedLine, "250 OK")
			isSingleLineOK := strings.HasPrefix(trimmedLine, "250 ") && !strings.HasPrefix(trimmedLine, "250-")
			isErrorLine := strings.HasPrefix(trimmedLine, "5") || strings.HasPrefix(trimmedLine, "4")


			if (isMultiLine && isFinalOK) || (!isMultiLine && (isSingleLineOK || isErrorLine)) {
				responseStr := strings.TrimSpace(responseBuffer.String())
				if updateCircuitTimeOnNewnym && strings.HasPrefix(command, "SIGNAL NEWNYM") && strings.HasPrefix(responseStr, "250 OK") {
					ti.LastCircuitRecreationTime = time.Now()
					log.Printf("Instance %d: LastCircuitRecreationTime updated to %v (NEWNYM)", ti.InstanceID, ti.LastCircuitRecreationTime)
				}
				return responseStr, nil
			}

			// Handle specific errors that might require action (like 515 Auth failed)
			if strings.HasPrefix(trimmedLine, "515") { // Authentication failed
				log.Printf("Instance %d: Received Tor error 515 for '%s'. Invalidating cookie. Full error: %s", ti.InstanceID, command, trimmedLine)
				ti.controlCookieHex = "" // Invalidate cookie
				if attempt == 0 { break } // Break inner loop to retry connection with fresh cookie
				return strings.TrimSpace(responseBuffer.String()), fmt.Errorf("tor error: %s", trimmedLine)
			}
		}
		conn.SetReadDeadline(time.Time{}) // Clear deadline before next attempt or exit
		if attempt == 0 { continue } // Go to next attempt (outer loop)
	}
	return "", fmt.Errorf("instance %d: SendTorCommand exhausted retries for command '%s'", ti.InstanceID, command)
}


func (ti *Instance) CheckHealth(ctx context.Context) bool {
	// ... (same as before, but uses new SendTorCommand signature)
	healthCtx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()

	type result struct {
		response string
		err      error
	}
	ch := make(chan result, 1)

	go func() {
		// For health check, NEWNYM is not implied, so updateCircuitTimeOnNewnym is false.
		// If health check needed to ensure a working circuit, it might send NEWNYM, but that's separate.
		resp, err := ti.SendTorCommand("GETINFO status/bootstrap-phase", false)
		ch <- result{resp, err}
	}()

	isCurrentlyHealthy := false
	var checkErrMessage string

	select {
	case <-healthCtx.Done():
		checkErrMessage = fmt.Sprintf("timed out for control host %s", ti.ControlHost)
	case res := <-ch:
		expectedContent := "status/bootstrap-phase=PROGRESS=100 TAG=done SUMMARY=\"Done\""
		if res.err == nil &&
			strings.Contains(res.response, "PROGRESS=100") &&
			strings.Contains(res.response, "TAG=done") {
			if strings.Contains(res.response, expectedContent) || strings.Contains(res.response, "PROGRESS=100 TAG=done") {
				isCurrentlyHealthy = true
				checkErrMessage = "Successfully bootstrapped"
			} else {
				isCurrentlyHealthy = true // Still consider it healthy if 100% and done
				checkErrMessage = fmt.Sprintf("bootstrap 100%%, TAG=done, but summary/prefix mismatch: '%s'", firstNChars(res.response, 150))
			}
		} else {
			if res.err != nil {
				checkErrMessage = fmt.Sprintf("error during GETINFO: %v. Response: '%s'", res.err, firstNChars(res.response, 100))
			} else {
				checkErrMessage = fmt.Sprintf("bootstrap not complete or unexpected response: '%s'", firstNChars(res.response, 150))
			}
		}
	}

	ti.Mu.Lock()
	if ti.IsHealthy != isCurrentlyHealthy {
		log.Printf("Instance %d: Health status changed to %v (was %v). Reason/Details: %s", ti.InstanceID, isCurrentlyHealthy, ti.IsHealthy, checkErrMessage)
	}
	if !isCurrentlyHealthy && ti.IsHealthy { // Transition from healthy to unhealthy
		ti.ConsecutiveFailures++
	} else if isCurrentlyHealthy {
		ti.ConsecutiveFailures = 0
	}
	ti.IsHealthy = isCurrentlyHealthy
	ti.LastHealthCheck = time.Now()
	ti.Mu.Unlock()
	return isCurrentlyHealthy
}

func (ti *Instance) initializeHTTPClientUnlocked() {
	// ... (same as before)
	proxyURL, err := url.Parse("socks5://" + ti.BackendSocksHost)
	if err != nil {
		log.Printf("Instance %d ERROR: Failed to parse proxy URL %s: %v. HTTP client not updated.", ti.InstanceID, ti.BackendSocksHost, err)
		ti.httpClient = nil // Ensure it's nil if setup fails
		return
	}

	// Use a net.Dialer with a timeout for the proxy connection itself
	proxyDialer := &net.Dialer{
		Timeout:   ti.appConfig.SocksTimeout, // Timeout for connecting to the SOCKS proxy
		KeepAlive: 30 * time.Second,
	}

	contextDialer, err := proxy.FromURL(proxyURL, proxyDialer)
	if err != nil {
		log.Printf("Instance %d ERROR: Failed to create proxy context dialer for %s: %v. HTTP client not updated.", ti.InstanceID, ti.BackendSocksHost, err)
		ti.httpClient = nil
		return
	}

	httpTransport := &http.Transport{
		Proxy:                 nil, // We are using DialContext for proxying
		DialContext:           contextDialer.(proxy.ContextDialer).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second, // Timeout for TLS handshake to the target server
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: ti.appConfig.SocksTimeout * 2, // Timeout for reading response headers from target
	}
	ti.httpClient = &http.Client{
		Transport: httpTransport,
		Timeout:   ti.appConfig.SocksTimeout * 3, // Overall timeout for the HTTP request
	}
}

func (ti *Instance) ReinitializeHTTPClient() {
	// ... (same as before)
	ti.Mu.Lock()
	defer ti.Mu.Unlock()
	ti.initializeHTTPClientUnlocked()
	log.Printf("Instance %d: HTTP client explicitly re-initialized.", ti.InstanceID)
}

func (ti *Instance) GetHTTPClient() *http.Client {
	// ... (same as before)
	ti.Mu.Lock()
	defer ti.Mu.Unlock()
	if ti.httpClient == nil {
		// This can happen if initialization failed earlier. Attempt to re-initialize.
		log.Printf("Instance %d: HTTP client was nil, attempting re-initialization.", ti.InstanceID)
		ti.initializeHTTPClientUnlocked()
		if ti.httpClient == nil {
			log.Printf("Instance %d: HTTP client re-initialization failed.", ti.InstanceID)
			// Return a temporary client that will likely fail, or handle error upstream
			return &http.Client{Timeout: 1 * time.Millisecond} // Fails fast
		}
	}
	return ti.httpClient
}

func (ti *Instance) SetExternalIP(newIP string) {
	// ... (same as before)
	ti.Mu.Lock()
	defer ti.Mu.Unlock()

	maskedNewIP := maskIP(newIP)
	maskedCurrentIP := maskIP(ti.ExternalIP)

	// log.Printf("Instance %d: SetExternalIP called with newIP (masked)='%s'. Current ti.ExternalIP (masked)='%s'", ti.InstanceID, maskedNewIP, maskedCurrentIP)
	if ti.ExternalIP != newIP {
		log.Printf("Instance %d: External IP changing from (masked) '%s' to (masked) '%s'. Updating LastIPChangeTime.", ti.InstanceID, maskedCurrentIP, maskedNewIP)
		ti.ExternalIP = newIP
		ti.LastIPChangeTime = time.Now()
		// log.Printf("Instance %d: LastIPChangeTime updated to %v", ti.InstanceID, ti.LastIPChangeTime)
	} else {
		// log.Printf("Instance %d: newIP (masked) '%s' is same as current ti.ExternalIP (masked) '%s'. LastIPChangeTime not updated.", ti.InstanceID, maskedNewIP, maskedCurrentIP)
	}
	ti.LastIPCheck = time.Now() // Always update LastIPCheck time
}

func (ti *Instance) GetExternalIPInfo() (ip string, lastCheck time.Time, lastChange time.Time) {
	// ... (same as before)
	ti.Mu.Lock()
	defer ti.Mu.Unlock()
	return ti.ExternalIP, ti.LastIPCheck, ti.LastIPChangeTime
}


// SetTorNodePolicy applies ExitNodes, EntryNodes, or ExcludeNodes to the Tor instance.
// policyKey should be "ExitNodes", "EntryNodes", or "ExcludeNodes".
// nodes can be a comma-separated list of country codes, IPs, fingerprints. Empty to clear.
// Returns the Tor control port response and any error.
func (ti *Instance) SetTorNodePolicy(policyKey string, nodes string) (string, error) {
	var cmd string
	if nodes == "" { // Clear the policy
		cmd = fmt.Sprintf("RESETCONF %s", policyKey)
	} else {
		// Tor expects nodes بدون quotes for SETCONF, e.g. SETCONF ExitNodes {us},{gb}
		// Or SETCONF ExitNodes 1.2.3.4,5.6.7.8
		// The use of {} for country codes is a common convention but Tor might just take the codes directly.
		// Let's assume direct comma-separated values are fine.
		cmd = fmt.Sprintf("SETCONF %s %s", policyKey, nodes)
	}

	// This command doesn't directly cause a NEWNYM, so updateCircuitTimeOnNewnym is false.
	// However, changing ExitNodes often implicitly causes Tor to build new circuits.
	response, err := ti.SendTorCommand(cmd, false)
	if err != nil {
		return response, fmt.Errorf("failed to send %s: %w", cmd, err)
	}

	if !strings.HasPrefix(response, "250 OK") {
		return response, fmt.Errorf("tor rejected %s: %s", cmd, response)
	}

	// Successfully set, update internal state
	ti.Mu.Lock()
	defer ti.Mu.Unlock()
	fullPolicy := ""
	if nodes != "" {
		fullPolicy = fmt.Sprintf("%s %s", policyKey, nodes)
	}

	switch policyKey {
	case "ExitNodes":
		ti.CurrentExitNodePolicy = fullPolicy
	case "EntryNodes":
		ti.CurrentEntryNodePolicy = fullPolicy
	case "ExcludeNodes":
		// ExcludeNodes is often combined with others. For simplicity, just store it.
		// More complex logic would be needed if we wanted to show the "effective" policy.
		// For now, we just store the last *applied* ExcludeNodes setting.
		// If ExcludeNodes is set, and then ExitNodes is set, Tor applies both.
		// RESETCONF ExcludeNodes would clear it.
		// This simple storage might not reflect the full combined state if multiple policies are used.
		// For now, assume users manage one primary policy type (e.g. ExitNodes) + ExcludeNodes.
		log.Printf("Instance %d: Note - ExcludeNodes policy set. Tor combines this with other node restrictions.", ti.InstanceID)
	}
	log.Printf("Instance %d: Successfully applied Tor node policy: %s", ti.InstanceID, cmd)
	return response, nil
}

// GetTorNodePolicies retrieves current node policies from the Tor instance.
func (ti *Instance) GetTorNodePolicies() (map[string]string, error) {
	policies := make(map[string]string)
	keys := []string{"ExitNodes", "EntryNodes", "ExcludeNodes", "GeoIPFile", "GeoIPv6File"}
	
	for _, key := range keys {
		// false for updateCircuitTimeOnNewnym as GETCONF doesn't trigger NEWNYM
		response, err := ti.SendTorCommand(fmt.Sprintf("GETCONF %s", key), false)
		if err != nil {
			log.Printf("Instance %d: Error getting Tor config for %s: %v", ti.InstanceID, key, err)
			// Continue trying to get other keys
			policies[key] = fmt.Sprintf("Error: %v", err)
			continue
		}
		// Typical response: "250 ExitNodes=US,CA" or "250 GeoIPFile=/path/to/geoip"
		// Or "250 ExcludeNodes" if it's set but empty (meaning exclude nothing explicitly by this setting alone)
		// Or "250 ExcludeNodes" if it was RESET.
		// If not set at all, Tor might return "552 Unrecognized configuration key" or similar for some keys if they aren't active.
		// Or it might return the default.
		
		parts := strings.SplitN(response, "=", 2)
		if strings.HasPrefix(response, "250 ") && len(parts) > 1 { // Key has a value
			value := strings.TrimSpace(parts[1])
			if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") { // Remove quotes if any
				value = value[1 : len(value)-1]
			}
			policies[key] = value
		} else if strings.HasPrefix(response, "250 ") { // Key is set but might be empty or a flag
			 policies[key] = strings.TrimPrefix(response, "250 ") // e.g. "ExitNodes" if it was reset
			 if strings.TrimSpace(policies[key]) == key { // If it just echoed the key, means it's effectively empty/default
				policies[key] = "(default/empty)"
			 }
		} else {
			policies[key] = fmt.Sprintf("Unexpected response: %s", firstNChars(response, 50))
		}
	}
	
	// Update internal cache from live values
	ti.Mu.Lock()
	if val, ok := policies["ExitNodes"]; ok && !strings.HasPrefix(val, "Error") && !strings.HasPrefix(val, "Unexpected") {
		ti.CurrentExitNodePolicy = fmt.Sprintf("ExitNodes %s", val)
		if val == "(default/empty)" { ti.CurrentExitNodePolicy = "" }
	}
	if val, ok := policies["EntryNodes"]; ok && !strings.HasPrefix(val, "Error") && !strings.HasPrefix(val, "Unexpected") {
		ti.CurrentEntryNodePolicy = fmt.Sprintf("EntryNodes %s", val)
		if val == "(default/empty)" { ti.CurrentEntryNodePolicy = "" }
	}
	// ExcludeNodes is more complex as it's additive. GETCONF will show the current value.
	if val, ok := policies["GeoIPFile"]; ok && !strings.HasPrefix(val, "Error") { ti.CurrentGeoIPFile = val }
	if val, ok := policies["GeoIPv6File"]; ok && !strings.HasPrefix(val, "Error") { ti.CurrentGeoIPv6File = val } // Corrected to hasPrefix
	ti.Mu.Unlock()

	return policies, nil
}


func firstNChars(s string, n int) string {
	// ... (same as before)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
