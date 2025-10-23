package tor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"torgo/internal/config"
	"torgo/internal/secmem"

	"golang.org/x/net/proxy"
)

type Instance struct {
	InstanceID        int
	controlHost       string
	backendSocksHost  string
	backendDNSHost    string
	AuthCookiePath    string
	DataDir           string
	mu                sync.Mutex
	httpClient        *http.Client
	activeControlConn net.Conn
	// Encrypted control cookie held only in memory
	controlCookieNonce        []byte
	controlCookieCipher       []byte
	isHealthy                 bool
	lastHealthCheck           time.Time
	consecutiveFailures       int
	externalIP                string
	lastIPCheck               time.Time
	lastIPChangeTime          time.Time
	lastDiversityRotate       time.Time
	lastCircuitRecreationTime time.Time
	activeConnections         atomic.Int64
	isDraining                atomic.Bool
	appConfig                 *config.AppConfig
}

func New(id int, appCfg *config.AppConfig) *Instance {
	controlPort := appCfg.ControlBasePort + id
	socksPort := appCfg.SocksBasePort + id
	dnsPort := appCfg.DNSBasePort + id

	dataDir := filepath.Join("/var/lib/tor", fmt.Sprintf("instance%d", id))
	authCookiePath := filepath.Join(dataDir, "control_auth_cookie")

	ti := &Instance{
		InstanceID:       id,
		controlHost:      fmt.Sprintf("127.0.0.1:%d", controlPort),
		backendSocksHost: fmt.Sprintf("127.0.0.1:%d", socksPort),
		backendDNSHost:   fmt.Sprintf("127.0.0.1:%d", dnsPort),
		AuthCookiePath:   authCookiePath,
		DataDir:          dataDir,
		appConfig:        appCfg,
	}
	ti.initializeHTTPClientUnlocked()
	return ti
}

func (ti *Instance) GetControlHost() string      { return ti.controlHost }
func (ti *Instance) GetBackendSocksHost() string { return ti.backendSocksHost }
func (ti *Instance) GetBackendDNSHost() string   { return ti.backendDNSHost }

func (ti *Instance) loadAndCacheControlCookieUnlocked(forceReload bool) error {
	if ti.controlCookieCipher != nil && !forceReload {
		return nil
	}
	cookieBytes, err := os.ReadFile(ti.AuthCookiePath)
	if err != nil {
		ti.clearCachedCookie()
		return fmt.Errorf("instance %d: failed to read auth cookie %s: %w", ti.InstanceID, ti.AuthCookiePath, err)
	}
	n, c, err := secmem.Seal(cookieBytes)
	secmem.Zeroize(cookieBytes)
	if err != nil {
		ti.clearCachedCookie()
		return fmt.Errorf("instance %d: failed to encrypt control cookie: %w", ti.InstanceID, err)
	}
	ti.controlCookieNonce = n
	ti.controlCookieCipher = c
	return nil
}

func (ti *Instance) clearCachedCookie() {
	if ti.controlCookieCipher != nil {
		secmem.Zeroize(ti.controlCookieCipher)
		ti.controlCookieCipher = nil
	}
	if ti.controlCookieNonce != nil {
		secmem.Zeroize(ti.controlCookieNonce)
		ti.controlCookieNonce = nil
	}
}

func (ti *Instance) connectToTorControlUnlocked() (net.Conn, *bufio.Reader, error) {
	if err := ti.loadAndCacheControlCookieUnlocked(ti.controlCookieCipher == nil); err != nil {
		return nil, nil, fmt.Errorf("instance %d: pre-connect cookie load failed: %w", ti.InstanceID, err)
	}

	conn, err := net.DialTimeout("tcp", ti.controlHost, 5*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("instance %d: failed to connect to control port %s: %w", ti.InstanceID, ti.controlHost, err)
	}

	plainCookie, err := secmem.Open(ti.controlCookieNonce, ti.controlCookieCipher)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("instance %d: failed to decrypt control cookie: %w", ti.InstanceID, err)
	}
	hexBuf := make([]byte, len(plainCookie)*2)
	hex.Encode(hexBuf, plainCookie)
	secmem.Zeroize(plainCookie)

	// Build AUTHENTICATE command without creating Go strings
	authCmd := make([]byte, 0, len("AUTHENTICATE ")+len(hexBuf)+2)
	authCmd = append(authCmd, []byte("AUTHENTICATE ")...)
	authCmd = append(authCmd, hexBuf...)
	authCmd = append(authCmd, '\r', '\n')

	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write(authCmd)
	conn.SetWriteDeadline(time.Time{})
	secmem.Zeroize(hexBuf)
	secmem.Zeroize(authCmd)
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
			log.Printf("Instance %d: Control port authentication failed. Invalidating cookie.", ti.InstanceID)
			ti.clearCachedCookie()
		}
		return nil, nil, fmt.Errorf("instance %d: tor control port authentication failed: %s", ti.InstanceID, trimmedStatus)
	}
	ti.activeControlConn = conn
	return conn, reader, nil
}

func (ti *Instance) CloseControlConnection() {
	ti.mu.Lock()
	defer ti.mu.Unlock()
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
					if ti.activeControlConn != nil {
						ti.activeControlConn.Close()
						ti.activeControlConn = nil
					}
					continue
				}
				return "", err
			}
		}

		conn.SetWriteDeadline(time.Now().Add(ti.appConfig.SocksTimeout))
		_, err = conn.Write([]byte(command + "\r\n"))
		conn.SetWriteDeadline(time.Time{})
		if err != nil {
			if ti.activeControlConn != nil {
				ti.activeControlConn.Close()
				ti.activeControlConn = nil
			}
			if attempt == 0 {
				continue
			}
			return "", err
		}

		conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		for {
			line, errRead := reader.ReadString('\n')
			if errRead != nil {
				conn.SetReadDeadline(time.Time{})
				if ti.activeControlConn != nil {
					ti.activeControlConn.Close()
					ti.activeControlConn = nil
				}
				return responseBuffer.String(), errRead
			}
			responseBuffer.WriteString(line)
			trimmedLine := strings.TrimSpace(line)
			if strings.HasPrefix(trimmedLine, "250 OK") || (strings.HasPrefix(trimmedLine, "250 ") && !strings.Contains(line, "-")) || strings.HasPrefix(trimmedLine, "5") {
				conn.SetReadDeadline(time.Time{})
				if command == "SIGNAL NEWNYM" && strings.HasPrefix(trimmedLine, "250 OK") {
					ti.lastCircuitRecreationTime = time.Now()
				}
				return responseBuffer.String(), nil
			}
		}
	}
	return "", fmt.Errorf("command %s failed after retries", command)
}

func (ti *Instance) CheckHealth(ctx context.Context) bool {
	healthCheckCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ch := make(chan struct {
		response string
		err      error
	}, 1)
	go func() {
		resp, err := ti.SendTorCommand("GETINFO status/bootstrap-phase")
		ch <- struct {
			response string
			err      error
		}{resp, err}
	}()
	var currentCheckHealthy bool
	select {
	case <-healthCheckCtx.Done():
		currentCheckHealthy = false
	case res := <-ch:
		if res.err == nil && strings.Contains(res.response, "PROGRESS=100") {
			currentCheckHealthy = true
		} else {
			currentCheckHealthy = false
		}
	}
	ti.mu.Lock()
	if ti.isHealthy != currentCheckHealthy {
		log.Printf("Instance %d: Health status -> %t (was %t).", ti.InstanceID, currentCheckHealthy, ti.isHealthy)
	}
	if !currentCheckHealthy {
		ti.consecutiveFailures++
	} else {
		ti.consecutiveFailures = 0
	}
	ti.isHealthy = currentCheckHealthy
	ti.lastHealthCheck = time.Now()
	ti.mu.Unlock()
	return currentCheckHealthy
}

func (ti *Instance) GetHealthStatus() (isHealthy bool, lastCheck time.Time, consecutiveFailures int) {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	return ti.isHealthy, ti.lastHealthCheck, ti.consecutiveFailures
}
func (ti *Instance) IsCurrentlyHealthy() bool {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	return ti.isHealthy
}
func (ti *Instance) IncrementActiveConnections() { ti.activeConnections.Add(1) }
func (ti *Instance) DecrementActiveConnections() { ti.activeConnections.Add(-1) }
func (ti *Instance) GetActiveConnections() int64 { return ti.activeConnections.Load() }
func (ti *Instance) IsDraining() bool            { return ti.isDraining.Load() }
func (ti *Instance) StartDraining()              { ti.isDraining.Store(true) }
func (ti *Instance) StopDraining()               { ti.isDraining.Store(false) }

func (ti *Instance) initializeHTTPClientUnlocked() {
	dialer, err := proxy.SOCKS5("tcp", ti.backendSocksHost, nil, &net.Dialer{
		Timeout:   ti.appConfig.SocksTimeout,
		KeepAlive: 30 * time.Second,
	})
	if err != nil {
		log.Printf("Inst %d ERR: Create SOCKS dialer for %s: %v. HTTP client set to nil.", ti.InstanceID, ti.backendSocksHost, err)
		ti.httpClient = nil
		return
	}

	// CORRECTED: The proxy.Dialer interface has a Dial method. We must wrap it in a
	// function that matches the http.Transport.DialContext signature.
	httpTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
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

func (ti *Instance) GetHTTPClient() *http.Client {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	if ti.httpClient == nil {
		ti.initializeHTTPClientUnlocked()
	}
	return ti.httpClient
}
func (ti *Instance) SetExternalIP(newIP string, checkTime time.Time) {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	if ti.externalIP != newIP {
		ti.externalIP = newIP
		if newIP != "" {
			ti.lastIPChangeTime = checkTime
		}
	}
	ti.lastIPCheck = checkTime
}
func (ti *Instance) GetExternalIPInfo() (ip string, lastCheck time.Time, lastChange time.Time) {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	return ti.externalIP, ti.lastIPCheck, ti.lastIPChangeTime
}
func (ti *Instance) GetCircuitTimestamps() (lastCircuitRec time.Time, lastDiversityRot time.Time) {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	return ti.lastCircuitRecreationTime, ti.lastDiversityRotate
}
func (ti *Instance) UpdateLastDiversityRotate() {
	ti.mu.Lock()
	ti.lastDiversityRotate = time.Now()
	ti.mu.Unlock()
}
func (ti *Instance) GetConfigSnapshot() map[string]interface{} {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	return map[string]interface{}{
		"instance_id":                ti.InstanceID,
		"control_host":               ti.controlHost,
		"backend_socks_host":         ti.backendSocksHost,
		"backend_dns_host":           ti.backendDNSHost,
		"is_healthy":                 ti.isHealthy,
		"last_health_check_at":       ti.lastHealthCheck.Format(time.RFC3339Nano),
		"consecutive_failures":       ti.consecutiveFailures,
		"external_ip":                ti.externalIP,
		"last_ip_check_at":           ti.lastIPCheck.Format(time.RFC3339Nano),
		"last_ip_change_at":          ti.lastIPChangeTime.Format(time.RFC3339Nano),
		"last_circuit_recreation_at": ti.lastCircuitRecreationTime.Format(time.RFC3339Nano),
		"last_diversity_rotate_at":   ti.lastDiversityRotate.Format(time.RFC3339Nano),
		"is_draining":                ti.IsDraining(),
		"active_connections":         ti.GetActiveConnections(),
	}
}
