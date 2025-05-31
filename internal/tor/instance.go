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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
	"torgo/internal/config"
)

type Instance struct {
	InstanceID       int
	controlHost      string; backendSocksHost string; backendDNSHost   string
	AuthCookiePath   string; DataDir          string
	mu                  sync.Mutex
	httpClient          *http.Client; activeControlConn   net.Conn; controlCookieHex    string
	isHealthy           bool; lastHealthCheck     time.Time; consecutiveFailures int
	externalIP          string; lastIPCheck         time.Time; lastIPChangeTime    time.Time
	lastDiversityRotate time.Time; lastCircuitRecreationTime time.Time
	appConfig *config.AppConfig
}

func New(id int, appCfg *config.AppConfig) *Instance {
	dataDir := filepath.Join("/var/lib/tor", fmt.Sprintf("instance%d", id))
	ti := &Instance{
		InstanceID:       id,
		controlHost:      fmt.Sprintf("127.0.0.1:%d", appCfg.ControlBasePort+id),
		backendSocksHost: fmt.Sprintf("127.0.0.1:%d", appCfg.SocksBasePort+id),
		backendDNSHost:   fmt.Sprintf("127.0.0.1:%d", appCfg.DNSBasePort+id),
		AuthCookiePath:   filepath.Join(dataDir, "control_auth_cookie"),
		DataDir:          dataDir, appConfig: appCfg,
	}
	ti.initializeHTTPClientUnlocked(); return ti
}
func (ti *Instance) GetControlHost() string { return ti.controlHost }
func (ti *Instance) GetBackendSocksHost() string { return ti.backendSocksHost }
func (ti *Instance) GetBackendDNSHost() string { return ti.backendDNSHost }

func (ti *Instance) loadAndCacheControlCookieUnlocked(forceReload bool) error {
	if ti.controlCookieHex != "" && !forceReload { return nil }
	cookieBytes, err := os.ReadFile(ti.AuthCookiePath)
	if err != nil { ti.controlCookieHex = ""; return fmt.Errorf("inst %d: read cookie %s: %w", ti.InstanceID, ti.AuthCookiePath, err) }
	ti.controlCookieHex = hex.EncodeToString(cookieBytes); return nil
}
func (ti *Instance) connectToTorControlUnlocked() (net.Conn, *bufio.Reader, error) {
	if err := ti.loadAndCacheControlCookieUnlocked(ti.controlCookieHex == ""); err != nil { return nil, nil, fmt.Errorf("inst %d: pre-conn cookie: %w", ti.InstanceID, err) }
	if ti.controlCookieHex == "" { return nil, nil, fmt.Errorf("inst %d: cookie empty from %s", ti.InstanceID, ti.AuthCookiePath) }
	conn, err := net.DialTimeout("tcp", ti.controlHost, 5*time.Second)
	if err != nil { return nil, nil, fmt.Errorf("inst %d: connect ctrl %s: %w", ti.InstanceID, ti.controlHost, err) }
	authCmd := fmt.Sprintf("AUTHENTICATE %s\r\n", ti.controlCookieHex)
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); _, err = conn.Write([]byte(authCmd)); conn.SetWriteDeadline(time.Time{})
	if err != nil { conn.Close(); return nil, nil, fmt.Errorf("inst %d: send AUTH: %w", ti.InstanceID, err) }
	reader := bufio.NewReader(conn); conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	statusLine, err := reader.ReadString('\n'); conn.SetReadDeadline(time.Time{})
	if err != nil { conn.Close(); return nil, nil, fmt.Errorf("inst %d: read auth resp: %w", ti.InstanceID, err) }
	trimmedStatus := strings.TrimSpace(statusLine)
	if !strings.HasPrefix(trimmedStatus, "250 OK") {
		conn.Close(); if strings.HasPrefix(trimmedStatus, "515") { ti.controlCookieHex = "" }
		return nil, nil, fmt.Errorf("inst %d: ctrl auth failed: %s", ti.InstanceID, trimmedStatus)
	}
	ti.activeControlConn = conn; return conn, reader, nil
}
func (ti *Instance) CloseControlConnection() { ti.mu.Lock(); ti.closeControlConnUnlocked(); ti.mu.Unlock() }
func (ti *Instance) closeControlConnUnlocked() { if ti.activeControlConn != nil { ti.activeControlConn.Close(); ti.activeControlConn = nil } }

func (ti *Instance) SendTorCommand(command string) (string, error) {
	ti.mu.Lock(); defer ti.mu.Unlock(); var conn net.Conn; var reader *bufio.Reader; var err error; var respBuf bytes.Buffer
	for attempt := 0; attempt < 2; attempt++ {
		respBuf.Reset()
		if ti.activeControlConn != nil { conn = ti.activeControlConn; reader = bufio.NewReader(conn)
		} else {
			conn, reader, err = ti.connectToTorControlUnlocked()
			if err != nil { if attempt == 0 { ti.closeControlConnUnlocked(); continue }; return "", fmt.Errorf("inst %d cmd '%s': connect fail: %w", ti.InstanceID, command, err) }
		}
		conn.SetWriteDeadline(time.Now().Add(ti.appConfig.SocksTimeout)); _, errWrite := conn.Write([]byte(command + "\r\n")); conn.SetWriteDeadline(time.Time{})
		if errWrite != nil {
			ti.closeControlConnUnlocked(); if attempt == 0 { continue }; return "", fmt.Errorf("inst %d cmd '%s': write fail: %w", ti.InstanceID, command, errWrite)
		}
		readDeadline := 10 * time.Second; if strings.HasPrefix(command, "GETINFO") { readDeadline = 20 * time.Second }; conn.SetReadDeadline(time.Now().Add(readDeadline))
		for {
			line, errRead := reader.ReadString('\n')
			if errRead != nil {
				conn.SetReadDeadline(time.Time{}); ti.closeControlConnUnlocked(); partial := strings.TrimSpace(respBuf.String())
				if command == "SIGNAL NEWNYM" && strings.HasPrefix(partial, "250 OK") { ti.lastCircuitRecreationTime = time.Now(); return partial, nil }
				if attempt == 0 && (errRead == io.EOF || strings.Contains(errRead.Error(), "timeout")) { break }
				return partial, fmt.Errorf("inst %d cmd '%s': read fail: %w. Part: '%s'", ti.InstanceID, command, errRead, partial)
			}
			respBuf.WriteString(line); trimmedLine := strings.TrimSpace(line)
			if strings.HasPrefix(trimmedLine, "650 ") { continue } // Async
			isFinal := (strings.HasPrefix(trimmedLine, "250 OK")) || (strings.HasPrefix(trimmedLine, "250 ") && !strings.HasPrefix(trimmedLine, "250-")) || (strings.HasPrefix(trimmedLine, "5"))
			if isFinal {
				conn.SetReadDeadline(time.Time{}); finalResp := strings.TrimSpace(respBuf.String())
				if command == "SIGNAL NEWNYM" && strings.HasPrefix(finalResp, "250 OK") { ti.lastCircuitRecreationTime = time.Now() }
				if strings.HasPrefix(finalResp, "515") { ti.controlCookieHex = ""; ti.closeControlConnUnlocked(); if attempt == 0 { break } }
				return finalResp, nil
			}
		}
		conn.SetReadDeadline(time.Time{}); if attempt == 0 { continue }
	}
	return "", fmt.Errorf("inst %d cmd '%s': retries exhausted. Last part: '%s'", ti.InstanceID, command, respBuf.String())
}

func (ti *Instance) CheckHealth(ctx context.Context) bool {
	healthCtx, cancel := context.WithTimeout(ctx, 15*time.Second); defer cancel()
	type res struct { response string; err error }; ch := make(chan res, 1)
	go func() { r, e := ti.SendTorCommand("GETINFO status/bootstrap-phase"); ch <- res{r,e} }()
	var healthy bool; var msg string
	select {
	case <-healthCtx.Done(): healthy = false; msg = fmt.Sprintf("health timeout for %s (inst %d)", ti.controlHost, ti.InstanceID)
	case r := <-ch:
		if r.err == nil && (strings.Contains(r.response, "PROGRESS=100 TAG=done SUMMARY=\"Done\"") || (strings.Contains(r.response, "PROGRESS=100") && strings.Contains(r.response, "TAG=done"))) {
			healthy = true; msg = "Bootstrapped"
		} else { healthy = false; if r.err != nil { msg = fmt.Sprintf("GETINFO err: %v. Resp: '%s'", r.err, firstNChars(r.response, 50)) } else { msg = fmt.Sprintf("bootstrap incomplete: '%s'", firstNChars(r.response, 70)) } }
	}
	ti.mu.Lock()
	if ti.isHealthy != healthy { log.Printf("Instance %d: Health -> %t (was %t). Reason: %s", ti.InstanceID, healthy, ti.isHealthy, msg) }
	if !healthy { ti.consecutiveFailures++ } else { ti.consecutiveFailures = 0 }
	ti.isHealthy = healthy; ti.lastHealthCheck = time.Now(); ti.mu.Unlock(); return healthy
}
func (ti *Instance) GetHealthStatus() (isHealthy bool, lastCheck time.Time, consecutiveFailures int) {
	ti.mu.Lock(); defer ti.mu.Unlock(); return ti.isHealthy, ti.lastHealthCheck, ti.consecutiveFailures
}
func (ti *Instance) IsCurrentlyHealthy() bool { ti.mu.Lock(); defer ti.mu.Unlock(); return ti.isHealthy }

func (ti *Instance) initializeHTTPClientUnlocked() {
	proxyURL, err := url.Parse("socks5://" + ti.backendSocksHost)
	if err != nil { log.Printf("Inst %d ERR: Parse SOCKS URL %s: %v. HTTP client nil.", ti.InstanceID, ti.backendSocksHost, err); ti.httpClient = nil; return }
	contextDialer, err := proxy.SOCKS5("tcp", ti.backendSocksHost, nil, &net.Dialer{Timeout: ti.appConfig.SocksTimeout, KeepAlive: 30 * time.Second})
	if err != nil { log.Printf("Inst %d ERR: Create SOCKS dialer for %s: %v. HTTP client nil.", ti.InstanceID, ti.backendSocksHost, err); ti.httpClient = nil; return }
	httpTransport := &http.Transport{ DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) { return contextDialer.Dial(network, addr) },
		MaxIdleConns: 10, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ExpectContinueTimeout: 1 * time.Second, ForceAttemptHTTP2: true,
	}
	ti.httpClient = &http.Client{ Transport: httpTransport, Timeout: ti.appConfig.SocksTimeout * 3 }
}
func (ti *Instance) ReinitializeHTTPClient() { ti.mu.Lock(); ti.initializeHTTPClientUnlocked(); ti.mu.Unlock() }
func (ti *Instance) GetHTTPClient() *http.Client {
	ti.mu.Lock(); defer ti.mu.Unlock(); if ti.httpClient == nil { ti.initializeHTTPClientUnlocked() }; return ti.httpClient
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
