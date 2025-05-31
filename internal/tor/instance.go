package tor

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
	// "net/url" // Removed: imported and not used
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
	"torgo/internal/config"
)

// maskIP partially hides an IP address for logging.
func maskIP(ipAddress string) string {
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
			// Simplified IPv6 mask: take first 2 groups, rest 'x'
			if len(parts) >= 2 {
				// Construct a masked representation, trying to keep original length somewhat
				masked := fmt.Sprintf("%s:%s:x:x:x:x:x:x", parts[0], parts[1])
				if len(masked) > len(ipAddress) {
					return masked[:len(ipAddress)]
				}
				return masked
			}
		}
	}
	return "ip_mask_failed" // Fallback
}

// Instance represents a single backend Tor process and its state.
type Instance struct {
	InstanceID       int
	controlHost      string // Use getter
	backendSocksHost string // Use getter
	backendDNSHost   string // Use getter
	AuthCookiePath   string
	DataDir          string

	mu                  sync.Mutex
	httpClient          *http.Client
	activeControlConn   net.Conn
	controlCookieHex    string
	isHealthy           bool      // Use getter
	lastHealthCheck     time.Time // Use getter
	consecutiveFailures int

	externalIP          string    // Last known external IP address
	lastIPCheck         time.Time // Timestamp of the last successful IP check
	lastIPChangeTime    time.Time // Timestamp of when the ExternalIP value actually changed
	lastDiversityRotate time.Time // Timestamp of the last rotation triggered by IP diversity logic

	lastCircuitRecreationTime time.Time // Timestamp of the last successful NEWNYM signal

	appConfig *config.AppConfig // Reference to global app config
}

// New creates a new Tor instance configuration.
func New(id int, appCfg *config.AppConfig) *Instance {
	controlPort := appCfg.ControlBasePort + id
	socksPort := appCfg.SocksBasePort + id
	dnsPort := appCfg.DNSBasePort + id // For the Tor instance's own DNS resolver

	dataDir := filepath.Join("/var/lib/tor", fmt.Sprintf("instance%d", id))
	authCookiePath := filepath.Join(dataDir, "control_auth_cookie")

	ti := &Instance{
		InstanceID:       id,
		controlHost:      fmt.Sprintf("127.0.0.1:%d", controlPort),
		backendSocksHost: fmt.Sprintf("127.0.0.1:%d", socksPort),
		backendDNSHost:   fmt.Sprintf("127.0.0.1:%d", dnsPort),
		AuthCookiePath:   authCookiePath,
		DataDir:          dataDir,
		isHealthy:        false, // Start as unhealthy until first check
		appConfig:        appCfg,
	}
	ti.initializeHTTPClientUnlocked() // Call without lock as it's during construction
	return ti
}

// Getters for host strings
func (ti *Instance) GetControlHost() string {
	return ti.controlHost
}

func (ti *Instance) GetBackendSocksHost() string {
	return ti.backendSocksHost
}

func (ti *Instance) GetBackendDNSHost() string {
	return ti.backendDNSHost
}

func (ti *Instance) loadAndCacheControlCookieUnlocked(forceReload bool) error {
	if ti.controlCookieHex != "" && !forceReload {
		return nil
	}
	cookieBytes, err := os.ReadFile(ti.AuthCookiePath)
	if err != nil {
		ti.controlCookieHex = "" // Clear if read fails
		return fmt.Errorf("instance %d: failed to read auth cookie %s: %w", ti.InstanceID, ti.AuthCookiePath, err)
	}
	ti.controlCookieHex = hex.EncodeToString(cookieBytes)
	return nil
}

func (ti *Instance) connectToTorControlUnlocked() (net.Conn, *bufio.Reader, error) {
	if err := ti.loadAndCacheControlCookieUnlocked(ti.controlCookieHex == ""); err != nil {
		return nil, nil, fmt.Errorf("instance %d: pre-connect cookie load failed: %w", ti.InstanceID, err)
	}
	if ti.controlCookieHex == "" {
		return nil, nil, fmt.Errorf("instance %d: control cookie is empty after load attempt from %s", ti.InstanceID, ti.AuthCookiePath)
	}

	conn, err := net.DialTimeout("tcp", ti.controlHost, 5*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("instance %d: failed to connect to control port %s: %w", ti.InstanceID, ti.controlHost, err)
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
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
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
			log.Printf("Instance %d: Control port authentication failed (Tor msg: %s). Invalidating cached cookie.", ti.InstanceID, trimmedStatus)
			ti.controlCookieHex = ""
		}
		return nil, nil, fmt.Errorf("instance %d: tor control port authentication failed: %s", ti.InstanceID, trimmedStatus)
	}
	ti.activeControlConn = conn
	return conn, reader, nil
}

func (ti *Instance) CloseControlConnection() {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	ti.closeControlConnUnlocked()
}

func (ti *Instance) closeControlConnUnlocked() {
	if ti.activeControlConn != nil {
		ti.activeControlConn.Close()
		ti.activeControlConn = nil
	}
}

func (ti *Instance) SendTorCommand(command string) (string, error) {
	ti.mu.Lock()
	defer ti.mu.Unlock()

	var conn net.Conn
	var reader *bufio.Reader
	var err error
	var responseBuffer bytes.Buffer

	for attempt := 0; attempt < 2; attempt++ {
		responseBuffer.Reset()
		if ti.activeControlConn != nil {
			conn = ti.activeControlConn
			reader = bufio.NewReader(conn)
		} else {
			conn, reader, err = ti.connectToTorControlUnlocked()
			if err != nil {
				if attempt == 0 {
					ti.closeControlConnUnlocked()
					continue
				}
				return "", fmt.Errorf("instance %d cmd '%s': connect failed after retries: %w", ti.InstanceID, command, err)
			}
		}

		conn.SetWriteDeadline(time.Now().Add(ti.appConfig.SocksTimeout))
		if _, errWrite := conn.Write([]byte(command + "\r\n")); errWrite != nil {
			conn.SetWriteDeadline(time.Time{})
			ti.closeControlConnUnlocked()
			if attempt == 0 { continue }
			return "", fmt.Errorf("instance %d cmd '%s': write failed after retries: %w", ti.InstanceID, command, errWrite)
		}
		conn.SetWriteDeadline(time.Time{})

		readDeadlineDuration := 10 * time.Second
		if strings.HasPrefix(command, "GETINFO") { readDeadlineDuration = 20 * time.Second }
		conn.SetReadDeadline(time.Now().Add(readDeadlineDuration))

		for {
			line, errRead := reader.ReadString('\n')
			if errRead != nil {
				conn.SetReadDeadline(time.Time{})
				ti.closeControlConnUnlocked()
				partialResponse := strings.TrimSpace(responseBuffer.String())
				if command == "SIGNAL NEWNYM" && strings.HasPrefix(partialResponse, "250 OK") {
					ti.lastCircuitRecreationTime = time.Now()
					return partialResponse, nil
				}
				if attempt == 0 && (errRead == io.EOF || strings.Contains(errRead.Error(), "timeout")) { break }
				return partialResponse, fmt.Errorf("instance %d cmd '%s': read failed: %w. Partial: '%s'", ti.InstanceID, command, errRead, partialResponse)
			}
			responseBuffer.WriteString(line)
			trimmedLine := strings.TrimSpace(line)
			if strings.HasPrefix(trimmedLine, "650 ") { continue } // Async event
			isFinalLine := (strings.HasPrefix(trimmedLine, "250 OK")) ||
				(strings.HasPrefix(trimmedLine, "250 ") && !strings.HasPrefix(trimmedLine, "250-")) ||
				(strings.HasPrefix(trimmedLine, "5"))
			if isFinalLine {
				conn.SetReadDeadline(time.Time{})
				finalResponse := strings.TrimSpace(responseBuffer.String())
				if command == "SIGNAL NEWNYM" && strings.HasPrefix(finalResponse, "250 OK") {
					ti.lastCircuitRecreationTime = time.Now()
				}
				if strings.HasPrefix(finalResponse, "515") {
					ti.controlCookieHex = ""
					ti.closeControlConnUnlocked()
					if attempt == 0 { break }
				}
				return finalResponse, nil
			}
		}
		conn.SetReadDeadline(time.Time{})
		if attempt == 0 { continue }
	}
	return "", fmt.Errorf("instance %d cmd '%s': exhausted retries. Last partial: '%s'", ti.InstanceID, command, responseBuffer.String())
}

func (ti *Instance) CheckHealth(ctx context.Context) bool {
	healthCheckCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	type result struct { response string; err error }
	ch := make(chan result, 1)
	go func() {
		resp, err := ti.SendTorCommand("GETINFO status/bootstrap-phase")
		ch <- result{resp, err}
	}()
	var currentCheckHealthy bool
	var checkErrMessage string
	select {
	case <-healthCheckCtx.Done():
		currentCheckHealthy = false
		checkErrMessage = fmt.Sprintf("health check timed out for %s (inst %d)", ti.controlHost, ti.InstanceID)
	case res := <-ch:
		if res.err == nil && (strings.Contains(res.response, "status/bootstrap-phase=PROGRESS=100 TAG=done SUMMARY=\"Done\"") || (strings.Contains(res.response, "PROGRESS=100") && strings.Contains(res.response, "TAG=done"))) {
			currentCheckHealthy = true
			checkErrMessage = "Bootstrapped"
		} else {
			currentCheckHealthy = false
			if res.err != nil { checkErrMessage = fmt.Sprintf("GETINFO error: %v. Resp: '%s'", res.err, firstNChars(res.response, 50))
			} else { checkErrMessage = fmt.Sprintf("bootstrap incomplete: '%s'", firstNChars(res.response, 70)) }
		}
	}
	ti.mu.Lock()
	if ti.isHealthy != currentCheckHealthy {
		log.Printf("Instance %d: Health status -> %t (was %t). Reason: %s", ti.InstanceID, currentCheckHealthy, ti.isHealthy, checkErrMessage)
	}
	if !currentCheckHealthy { ti.consecutiveFailures++
	} else { ti.consecutiveFailures = 0 }
	ti.isHealthy = currentCheckHealthy; ti.lastHealthCheck = time.Now(); ti.mu.Unlock(); return currentCheckHealthy
}

func (ti *Instance) GetHealthStatus() (isHealthy bool, lastCheck time.Time, consecutiveFailures int) {
	ti.mu.Lock(); defer ti.mu.Unlock(); return ti.isHealthy, ti.lastHealthCheck, ti.consecutiveFailures
}
func (ti *Instance) IsCurrentlyHealthy() bool { ti.mu.Lock(); defer ti.mu.Unlock(); return ti.isHealthy }

func (ti *Instance) initializeHTTPClientUnlocked() {
	contextDialer, err := proxy.SOCKS5("tcp", ti.backendSocksHost, nil, &net.Dialer{
		Timeout:   ti.appConfig.SocksTimeout, 
		KeepAlive: 30 * time.Second,          
	})
	if err != nil {
		log.Printf("Inst %d ERR: Create SOCKS dialer for %s: %v. HTTP client set to nil.", ti.InstanceID, ti.backendSocksHost, err)
		ti.httpClient = nil
		return
	}

	httpTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return contextDialer.Dial(network, addr)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second, 
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	ti.httpClient = &http.Client{
		Transport: httpTransport,
		Timeout:   ti.appConfig.SocksTimeout * 3, 
	}
}

func (ti *Instance) ReinitializeHTTPClient() {
	ti.mu.Lock(); defer ti.mu.Unlock(); ti.initializeHTTPClientUnlocked()
	log.Printf("Instance %d: HTTP client re-initialized.", ti.InstanceID)
}
func (ti *Instance) GetHTTPClient() *http.Client {
	ti.mu.Lock(); defer ti.mu.Unlock(); if ti.httpClient == nil { ti.initializeHTTPClientUnlocked() }
	return ti.httpClient
}
func (ti *Instance) SetExternalIP(newIP string, checkTime time.Time) {
	ti.mu.Lock(); defer ti.mu.Unlock()
	if ti.externalIP != newIP { ti.externalIP = newIP; if newIP != "" { ti.lastIPChangeTime = checkTime } }
	ti.lastIPCheck = checkTime
}
func (ti *Instance) GetExternalIPInfo() (ip string, lastCheck time.Time, lastChange time.Time) {
	ti.mu.Lock(); defer ti.mu.Unlock(); return ti.externalIP, ti.lastIPCheck, ti.lastIPChangeTime
}
func (ti *Instance) GetCircuitTimestamps() (lastCircuitRec time.Time, lastDiversityRot time.Time) {
	ti.mu.Lock(); defer ti.mu.Unlock(); return ti.lastCircuitRecreationTime, ti.lastDiversityRotate
}
func (ti *Instance) UpdateLastDiversityRotate() { ti.mu.Lock(); ti.lastDiversityRotate = time.Now(); ti.mu.Unlock() }
func (ti *Instance) GetConfigSnapshot() map[string]interface{} {
	ti.mu.Lock(); defer ti.mu.Unlock()
	return map[string]interface{}{
		"instance_id": ti.InstanceID, "control_host": ti.controlHost, "backend_socks_host": ti.backendSocksHost, "backend_dns_host": ti.backendDNSHost,
		"is_healthy": ti.isHealthy, "last_health_check_at": ti.lastHealthCheck.Format(time.RFC3339Nano), "consecutive_failures": ti.consecutiveFailures,
		"external_ip": ti.externalIP, "last_ip_check_at": ti.lastIPCheck.Format(time.RFC3339Nano), "last_ip_change_at": ti.lastIPChangeTime.Format(time.RFC3339Nano),
		"last_circuit_recreation_at": ti.lastCircuitRecreationTime.Format(time.RFC3339Nano), "last_diversity_rotate_at": ti.lastDiversityRotate.Format(time.RFC3339Nano),
		"auth_cookie_path": ti.AuthCookiePath, "data_dir": ti.DataDir,
	}
}
func firstNChars(s string, n int) string { if len(s) > n { return s[:n] + "..." }; return s }
