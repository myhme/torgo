package torinstance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog" // Import slog
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

type PerformanceMetrics struct {
	LatencyMilliSeconds int64     `json:"latency_ms"`       
	DownloadSpeedKBps   float64   `json:"download_speed_kbps"` 
	LastTestTime        time.Time `json:"last_test_time"`
	TestTarget          string    `json:"test_target"` 
	TestFailures        int       `json:"test_failures"` 
	IsStale             bool      `json:"is_stale"`      
}

func maskIP(ipAddress string) string {
	if ipAddress == "" { return "empty" }
	ip := net.ParseIP(ipAddress)
	if ip == nil { return "invalid_ip_format" }
	if ip.To4() != nil {
		parts := strings.Split(ipAddress, ".")
		if len(parts) == 4 { return fmt.Sprintf("%s.%s.x.x", parts[0], parts[1]) }
	} else { 
		parts := strings.Split(ipAddress, ":")
		if len(parts) > 2 {
			maskedParts := []string{}
			for i, part := range parts {
				if i < 2 { maskedParts = append(maskedParts, part)
				} else { if len(maskedParts) < 4 { maskedParts = append(maskedParts, "x") } }
			}
			finalParts := []string{}
			for i := 0; i < len(parts) && i < 4; i++ {
				if i < len(maskedParts) { finalParts = append(finalParts, maskedParts[i])
				} else { finalParts = append(finalParts, "x") }
			}
			return strings.Join(finalParts, ":")
		}
	}
	return "ip_mask_failed"
}

type Instance struct {
	InstanceID       int
	ControlHost      string
	BackendSocksHost string
	BackendDNSHost   string
	AuthCookiePath   string
	DataDir          string

	Mu                  sync.Mutex 
	httpClient          *http.Client
	activeControlConn   net.Conn
	controlCookieHex    string
	IsHealthy           bool
	LastHealthCheck     time.Time
	ConsecutiveFailures int 

	ExternalIP          string
	LastIPCheck         time.Time 
	LastIPChangeTime    time.Time 
	LastDiversityRotate time.Time 

	LastCircuitRecreationTime time.Time 

	ActiveProxyConnections int32 

	PerfMetrics map[string]*PerformanceMetrics 

	CurrentExitNodePolicy   string 
	CurrentEntryNodePolicy  string
	CurrentGeoIPFile        string
	CurrentGeoIPv6File      string

	appConfig *config.AppConfig
}

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
		LastCircuitRecreationTime: initialTime, 
		LastIPChangeTime:          initialTime,
		LastDiversityRotate:       initialTime,
		ActiveProxyConnections:    0,
		PerfMetrics:               make(map[string]*PerformanceMetrics),
		appConfig:                 appCfg,
	}
	ti.Mu.Lock()
	ti.initializeHTTPClientUnlocked()
	for alias := range appCfg.LatencyTestTargets {
		ti.PerfMetrics[alias+"_latency"] = &PerformanceMetrics{TestTarget: alias + "_latency"}
	}
	if appCfg.SpeedTestTargetURL != "" && appCfg.SpeedTestTargetBytes > 0 {
		ti.PerfMetrics["default_speed"] = &PerformanceMetrics{TestTarget: "default_speed"}
	}
	ti.Mu.Unlock()
	slog.Debug("New Tor instance created.", "instance_id", id, "control_host", ti.ControlHost)
	return ti
}

func (ti *Instance) UpdatePerfMetric(targetAlias string, latencyMs int64, speedKBps float64, testFailed bool) {
	ti.Mu.Lock()
	defer ti.Mu.Unlock()

	metric, ok := ti.PerfMetrics[targetAlias]
	if !ok {
		metric = &PerformanceMetrics{TestTarget: targetAlias}
		ti.PerfMetrics[targetAlias] = metric
	}
	metric.LastTestTime = time.Now()
	metric.IsStale = false 
	if testFailed {
		metric.TestFailures++
	} else {
		metric.LatencyMilliSeconds = latencyMs
		metric.DownloadSpeedKBps = speedKBps
		metric.TestFailures = 0
	}
	slog.Debug("Performance metric updated.", 
		"instance_id", ti.InstanceID, 
		"target_alias", targetAlias, 
		"latency_ms", latencyMs, 
		"speed_kbps", speedKBps, 
		"failed", testFailed,
		"failure_count", metric.TestFailures,
	)
}

func (ti *Instance) GetPerfMetrics() map[string]PerformanceMetrics {
	ti.Mu.Lock()
	defer ti.Mu.Unlock()
	metricsCopy := make(map[string]PerformanceMetrics)
	staleDuration := ti.appConfig.PerfTestInterval + (ti.appConfig.PerfTestInterval / 2) 
	for key, metricPtr := range ti.PerfMetrics {
		copiedMetric := *metricPtr 
		if !copiedMetric.LastTestTime.IsZero() && time.Since(copiedMetric.LastTestTime) > staleDuration {
			copiedMetric.IsStale = true
		}
		metricsCopy[key] = copiedMetric
	}
	return metricsCopy
}

func (ti *Instance) IncrementActiveProxyConnections() { atomic.AddInt32(&ti.ActiveProxyConnections, 1) }
func (ti *Instance) DecrementActiveProxyConnections() { atomic.AddInt32(&ti.ActiveProxyConnections, -1) }
func (ti *Instance) GetActiveProxyConnections() int32 { return atomic.LoadInt32(&ti.ActiveProxyConnections) }

func (ti *Instance) loadAndCacheControlCookieUnlocked(forceReload bool) error {
	if ti.controlCookieHex != "" && !forceReload { return nil }
	cookieBytes, err := os.ReadFile(ti.AuthCookiePath)
	if err != nil {
		ti.controlCookieHex = ""
		// No slog here as it's called under lock, and might be during initial setup
		return fmt.Errorf("instance %d: failed to read cookie %s: %w", ti.InstanceID, ti.AuthCookiePath, err)
	}
	ti.controlCookieHex = hex.EncodeToString(cookieBytes)
	return nil
}

func (ti *Instance) connectToTorControlUnlocked() (net.Conn, *bufio.Reader, error) {
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
			// Logged by caller if needed, this function just returns error
			ti.controlCookieHex = "" // Invalidate cookie
		}
		return nil, nil, fmt.Errorf("instance %d: tor control port authentication failed: %s", ti.InstanceID, trimmedStatus)
	}
	ti.activeControlConn = conn
	return conn, reader, nil
}

func (ti *Instance) CloseControlConnUnlocked() {
	if ti.activeControlConn != nil {
		ti.activeControlConn.Close()
		ti.activeControlConn = nil
	}
}

func (ti *Instance) SendTorCommand(command string, updateCircuitTimeOnNewnym bool) (string, error) {
	ti.Mu.Lock()
	defer ti.Mu.Unlock()

	var conn net.Conn
	var reader *bufio.Reader
	var err error
	logger := slog.With("instance_id", ti.InstanceID, "command", command)

	for attempt := 0; attempt < 2; attempt++ {
		if ti.activeControlConn != nil {
			conn = ti.activeControlConn
			reader = bufio.NewReader(conn)
		} else {
			conn, reader, err = ti.connectToTorControlUnlocked()
			if err != nil {
				if attempt == 0 {
					logger.Warn("Tor control connection attempt failed, retrying...", "attempt", attempt+1, slog.Any("error", err))
					ti.CloseControlConnUnlocked()
					if strings.Contains(err.Error(), "authentication failed") {
						ti.controlCookieHex = "" 
					}
					continue
				}
				logger.Error("Tor control connection failed after retries.", slog.Any("error", err))
				return "", fmt.Errorf("instance %d SendTorCommand: connection phase failed after retries: %w", ti.InstanceID, err)
			}
		}

		conn.SetWriteDeadline(time.Now().Add(ti.appConfig.SocksTimeout))
		if _, errWrite := conn.Write([]byte(command + "\r\n")); errWrite != nil {
			conn.SetWriteDeadline(time.Time{})
			ti.CloseControlConnUnlocked()
			logger.Warn("Write failed for Tor command, connection closed.", "attempt", attempt+1, slog.Any("error", errWrite))
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
				if errRead == io.EOF && responseBuffer.Len() > 0 {
					if updateCircuitTimeOnNewnym && strings.HasPrefix(command, "SIGNAL NEWNYM") && strings.HasPrefix(responseStrPartial, "250 OK") {
						ti.LastCircuitRecreationTime = time.Now()
						logger.Info("LastCircuitRecreationTime updated (NEWNYM, EOF path).", "new_time", ti.LastCircuitRecreationTime.Format(time.RFC3339))
					}
					return responseStrPartial, nil 
				}
				if attempt == 0 { 
					logger.Warn("Read failed during Tor command, will retry connection.", "attempt", attempt+1, slog.Any("error", errRead), "partial_response", responseStrPartial)
					break 
				}
				logger.Error("Failed to read full response for Tor command after retries.", slog.Any("error", errRead), "partial_response", responseStrPartial)
				return responseBuffer.String(), fmt.Errorf("instance %d: failed to read full response for '%s': %w. Partial: '%s'", ti.InstanceID, command, errRead, responseBuffer.String())
			}
			responseBuffer.WriteString(line)
			trimmedLine := strings.TrimSpace(line)
			isFinalOK := strings.HasPrefix(trimmedLine, "250 OK")
			isSingleLineOK := strings.HasPrefix(trimmedLine, "250 ") && !strings.HasPrefix(trimmedLine, "250-")
			isErrorLine := strings.HasPrefix(trimmedLine, "5") || strings.HasPrefix(trimmedLine, "4")

			if (isMultiLine && isFinalOK) || (!isMultiLine && (isSingleLineOK || isErrorLine)) {
				responseStr := strings.TrimSpace(responseBuffer.String())
				if updateCircuitTimeOnNewnym && strings.HasPrefix(command, "SIGNAL NEWNYM") && strings.HasPrefix(responseStr, "250 OK") {
					ti.LastCircuitRecreationTime = time.Now()
					logger.Info("LastCircuitRecreationTime updated (NEWNYM).", "new_time", ti.LastCircuitRecreationTime.Format(time.RFC3339))
				}
				return responseStr, nil
			}
			if strings.HasPrefix(trimmedLine, "515") { 
				logger.Warn("Tor control authentication failed (515), invalidating cookie.", "error_line", trimmedLine)
				ti.controlCookieHex = "" 
				if attempt == 0 { break } 
				return strings.TrimSpace(responseBuffer.String()), fmt.Errorf("tor error: %s", trimmedLine)
			}
		}
		conn.SetReadDeadline(time.Time{}) 
		if attempt == 0 { continue } 
	}
	return "", fmt.Errorf("instance %d: SendTorCommand exhausted retries for command '%s'", ti.InstanceID, command)
}

func (ti *Instance) CheckHealth(ctx context.Context) bool {
	healthCtx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	logger := slog.With("instance_id", ti.InstanceID, "operation", "CheckHealth")

	type result struct { response string; err error }
	ch := make(chan result, 1)

	go func() {
		resp, err := ti.SendTorCommand("GETINFO status/bootstrap-phase", false)
		ch <- result{resp, err}
	}()

	isCurrentlyHealthy := false
	var checkErrMessage string

	select {
	case <-healthCtx.Done():
		checkErrMessage = fmt.Sprintf("timed out for control host %s", ti.ControlHost)
		logger.Warn("Health check timed out.", "control_host", ti.ControlHost)
	case res := <-ch:
		expectedContent := "status/bootstrap-phase=PROGRESS=100 TAG=done SUMMARY=\"Done\""
		if res.err == nil && strings.Contains(res.response, "PROGRESS=100") && strings.Contains(res.response, "TAG=done") {
			if strings.Contains(res.response, expectedContent) || strings.Contains(res.response, "PROGRESS=100 TAG=done") {
				isCurrentlyHealthy = true
				checkErrMessage = "Successfully bootstrapped"
			} else {
				isCurrentlyHealthy = true 
				checkErrMessage = fmt.Sprintf("bootstrap 100%%, TAG=done, but summary/prefix mismatch: '%s'", FirstNChars(res.response, 150))
			}
		} else {
			if res.err != nil {
				checkErrMessage = fmt.Sprintf("error during GETINFO: %v. Response: '%s'", res.err, FirstNChars(res.response, 100))
				logger.Warn("Health check GETINFO error.", slog.Any("error", res.err), "response_preview", FirstNChars(res.response, 100))
			} else {
				checkErrMessage = fmt.Sprintf("bootstrap not complete or unexpected response: '%s'", FirstNChars(res.response, 150))
				logger.Warn("Health check bootstrap not complete or unexpected response.", "response_preview", FirstNChars(res.response, 150))
			}
		}
	}

	ti.Mu.Lock()
	if ti.IsHealthy != isCurrentlyHealthy {
		logger.Info("Health status changed.", "new_status_healthy", isCurrentlyHealthy, "previous_status_healthy", ti.IsHealthy, "reason", checkErrMessage)
	}
	if !isCurrentlyHealthy && ti.IsHealthy { 
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
	logger := slog.With("instance_id", ti.InstanceID, "backend_socks_host", ti.BackendSocksHost)
	proxyURL, err := url.Parse("socks5://" + ti.BackendSocksHost)
	if err != nil {
		logger.Error("Failed to parse proxy URL for HTTP client.", slog.Any("error", err))
		ti.httpClient = nil 
		return
	}
	proxyDialer := &net.Dialer{ Timeout: ti.appConfig.SocksTimeout, KeepAlive: 30 * time.Second }
	contextDialer, err := proxy.FromURL(proxyURL, proxyDialer)
	if err != nil {
		logger.Error("Failed to create proxy context dialer for HTTP client.", slog.Any("error", err))
		ti.httpClient = nil
		return
	}
	httpTransport := &http.Transport{
		Proxy: nil, DialContext: contextDialer.(proxy.ContextDialer).DialContext,
		ForceAttemptHTTP2: true, MaxIdleConns: 10, IdleConnTimeout: 90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second, ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: ti.appConfig.SocksTimeout * 2,
	}
	ti.httpClient = &http.Client{ Transport: httpTransport, Timeout: ti.appConfig.SocksTimeout * 3 }
	logger.Debug("HTTP client initialized/re-initialized.")
}

func (ti *Instance) ReinitializeHTTPClient() {
	ti.Mu.Lock()
	defer ti.Mu.Unlock()
	ti.initializeHTTPClientUnlocked() // Slog call is inside initializeHTTPClientUnlocked
}

func (ti *Instance) GetHTTPClient() *http.Client {
	ti.Mu.Lock()
	defer ti.Mu.Unlock()
	if ti.httpClient == nil {
		slog.Warn("HTTP client was nil, attempting re-initialization.", "instance_id", ti.InstanceID)
		ti.initializeHTTPClientUnlocked()
		if ti.httpClient == nil {
			slog.Error("HTTP client re-initialization failed.", "instance_id", ti.InstanceID)
			return &http.Client{Timeout: 1 * time.Millisecond} 
		}
	}
	return ti.httpClient
}

func (ti *Instance) SetExternalIP(newIP string) {
	ti.Mu.Lock()
	defer ti.Mu.Unlock()
	logger := slog.With("instance_id", ti.InstanceID)
	maskedNewIP := maskIP(newIP)
	maskedCurrentIP := maskIP(ti.ExternalIP)

	if ti.ExternalIP != newIP {
		logger.Info("External IP changing.", "from_ip_masked", maskedCurrentIP, "to_ip_masked", maskedNewIP)
		ti.ExternalIP = newIP
		ti.LastIPChangeTime = time.Now()
	} else {
		logger.Debug("SetExternalIP called with same IP.", "ip_masked", maskedNewIP)
	}
	ti.LastIPCheck = time.Now()
}

func (ti *Instance) GetExternalIPInfo() (ip string, lastCheck time.Time, lastChange time.Time) {
	ti.Mu.Lock()
	defer ti.Mu.Unlock()
	return ti.ExternalIP, ti.LastIPCheck, ti.LastIPChangeTime
}

func (ti *Instance) SetTorNodePolicy(policyKey string, nodes string) (string, error) {
	var cmd string
	if nodes == "" { 
		cmd = fmt.Sprintf("RESETCONF %s", policyKey)
	} else {
		cmd = fmt.Sprintf("SETCONF %s %s", policyKey, nodes)
	}
	logger := slog.With("instance_id", ti.InstanceID, "policy_key", policyKey, "nodes", nodes, "command", cmd)
	
	response, err := ti.SendTorCommand(cmd, false)
	if err != nil {
		logger.Error("Failed to send node policy command to Tor.", slog.Any("error", err), "tor_response", response)
		return response, fmt.Errorf("failed to send %s: %w", cmd, err)
	}
	if !strings.HasPrefix(response, "250 OK") {
		logger.Error("Tor rejected node policy command.", "tor_response", response)
		return response, fmt.Errorf("tor rejected %s: %s", cmd, response)
	}

	ti.Mu.Lock()
	defer ti.Mu.Unlock()
	fullPolicy := ""; if nodes != "" { fullPolicy = fmt.Sprintf("%s %s", policyKey, nodes) }
	switch policyKey {
	case "ExitNodes": ti.CurrentExitNodePolicy = fullPolicy
	case "EntryNodes": ti.CurrentEntryNodePolicy = fullPolicy
	case "ExcludeNodes": logger.Debug("ExcludeNodes policy set. Tor combines this with other restrictions.")
	}
	logger.Info("Successfully applied Tor node policy.")
	return response, nil
}

func (ti *Instance) GetTorNodePolicies() (map[string]string, error) {
	policies := make(map[string]string)
	keys := []string{"ExitNodes", "EntryNodes", "ExcludeNodes", "GeoIPFile", "GeoIPv6File"}
	logger := slog.With("instance_id", ti.InstanceID)
	
	var firstError error
	for _, key := range keys {
		response, err := ti.SendTorCommand(fmt.Sprintf("GETCONF %s", key), false)
		if err != nil {
			logger.Warn("Error getting Tor config for key.", "key", key, slog.Any("error", err))
			policies[key] = fmt.Sprintf("Error: %v", err)
			if firstError == nil { firstError = err } // Capture first error
			continue
		}
		parts := strings.SplitN(response, "=", 2)
		if strings.HasPrefix(response, "250 ") && len(parts) > 1 { 
			value := strings.TrimSpace(parts[1])
			if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") { value = value[1 : len(value)-1] }
			policies[key] = value
		} else if strings.HasPrefix(response, "250 ") { 
			 policies[key] = strings.TrimPrefix(response, "250 ") 
			 if strings.TrimSpace(policies[key]) == key { policies[key] = "(default/empty)" }
		} else {
			policies[key] = fmt.Sprintf("Unexpected response: %s", FirstNChars(response, 50)) // Use exported function
			logger.Warn("Unexpected response from GETCONF.", "key", key, "response_preview", FirstNChars(response,50))
		}
	}
	
	ti.Mu.Lock()
	if val, ok := policies["ExitNodes"]; ok && !strings.HasPrefix(val, "Error") && !strings.HasPrefix(val, "Unexpected") {
		ti.CurrentExitNodePolicy = fmt.Sprintf("ExitNodes %s", val); if val == "(default/empty)" { ti.CurrentExitNodePolicy = "" }
	}
	if val, ok := policies["EntryNodes"]; ok && !strings.HasPrefix(val, "Error") && !strings.HasPrefix(val, "Unexpected") {
		ti.CurrentEntryNodePolicy = fmt.Sprintf("EntryNodes %s", val); if val == "(default/empty)" { ti.CurrentEntryNodePolicy = "" }
	}
	if val, ok := policies["GeoIPFile"]; ok && !strings.HasPrefix(val, "Error") { ti.CurrentGeoIPFile = val }
	if val, ok := policies["GeoIPv6File"]; ok && !strings.HasPrefix(val, "Error") { ti.CurrentGeoIPv6File = val } 
	ti.Mu.Unlock()

	return policies, firstError 
}

// FirstNChars returns the first N characters of a string, or the whole string if shorter.
// Appends "..." if truncated.
func FirstNChars(s string, n int) string {
	if len(s) > n { return s[:n] + "..." }
	return s
}
