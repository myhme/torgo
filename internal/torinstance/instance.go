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
	"time"

	"golang.org/x/net/proxy"
	"torgo/internal/config" 
)

// Instance represents a single backend Tor process and its state.
type Instance struct {
	InstanceID       int
	ControlHost      string 
	BackendSocksHost string 
	BackendDNSHost   string 
	AuthCookiePath   string
	DataDir          string

	Mu                sync.Mutex 
	httpClient        *http.Client 
	activeControlConn net.Conn
	controlCookieHex  string    
	IsHealthy         bool      
	LastHealthCheck   time.Time 
	ConsecutiveFailures int     
	
	// Fields for IP Diversity Management
	ExternalIP          string    // Last known external IP address
	LastIPCheck         time.Time // Timestamp of the last successful IP check
	LastDiversityRotate time.Time // Timestamp of the last rotation triggered by IP diversity logic

	appConfig *config.AppConfig 
}

// New creates a new Tor instance configuration.
func New(id int, appCfg *config.AppConfig) *Instance {
	controlPort := appCfg.ControlBasePort + id
	socksPort := appCfg.SocksBasePort + id
	dnsPort := appCfg.DNSBasePort + id

	ti := &Instance{
		InstanceID:       id,
		ControlHost:      fmt.Sprintf("127.0.0.1:%d", controlPort),
		BackendSocksHost: fmt.Sprintf("127.0.0.1:%d", socksPort),
		BackendDNSHost:   fmt.Sprintf("127.0.0.1:%d", dnsPort),
		AuthCookiePath:   fmt.Sprintf("/var/lib/tor/instance%d/control_auth_cookie", id),
		DataDir:          fmt.Sprintf("/var/lib/tor/instance%d", id),
		IsHealthy:        false,
		appConfig:        appCfg,
	}
	ti.Mu.Lock()
	ti.initializeHTTPClientUnlocked()
	ti.Mu.Unlock()
	return ti
}

func (ti *Instance) loadAndCacheControlCookieUnlocked(forceReload bool) error {
	// Assumes ti.Mu is locked
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
	// Assumes ti.Mu is locked
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
	if ti.activeControlConn != nil {
		ti.activeControlConn.Close()
		ti.activeControlConn = nil
	}
}

func (ti *Instance) SendTorCommand(command string) (string, error) {
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
						ti.controlCookieHex = "" 
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
		isMultiLine := strings.HasPrefix(command, "GETINFO")
		readDeadlineDuration := 10 * time.Second 
		if isMultiLine { readDeadlineDuration = 20 * time.Second }
		conn.SetReadDeadline(time.Now().Add(readDeadlineDuration))

		for {
			line, errRead := reader.ReadString('\n')
			if errRead != nil {
				conn.SetReadDeadline(time.Time{}) 
				ti.CloseControlConnUnlocked()    
				// log.Printf("Instance %d: Read failed for command '%s' (%v), connection closed. Attempt %d. Partial: '%s'", ti.InstanceID, command, errRead, attempt+1, responseBuffer.String())
				if errRead == io.EOF && responseBuffer.Len() > 0 { 
					return strings.TrimSpace(responseBuffer.String()), nil
				}
				if attempt == 0 { break } 
				return responseBuffer.String(), fmt.Errorf("instance %d: failed to read full response for '%s': %w. Partial: '%s'", ti.InstanceID, command, errRead, responseBuffer.String())
			}
			responseBuffer.WriteString(line)
			trimmedLine := strings.TrimSpace(line)
			if strings.HasPrefix(trimmedLine, "250 OK") { return strings.TrimSpace(responseBuffer.String()), nil } 
			if strings.HasPrefix(trimmedLine, "250 ") && !strings.HasPrefix(trimmedLine, "250-") && !isMultiLine { return strings.TrimSpace(responseBuffer.String()), nil } 
			if strings.HasPrefix(trimmedLine, "5") { 
				if strings.HasPrefix(trimmedLine, "515") {
					log.Printf("Instance %d: Received Tor error 515 for '%s'. Invalidating cookie for retry. Full error: %s", ti.InstanceID, command, trimmedLine)
					ti.controlCookieHex = ""
				} else {
					// log.Printf("Instance %d: Received Tor error response for command '%s': %s", ti.InstanceID, command, trimmedLine)
				}
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

	type result struct { response string; err error }
	ch := make(chan result, 1)

	go func() {
		resp, err := ti.SendTorCommand("GETINFO status/bootstrap-phase")
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
				isCurrentlyHealthy = true 
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
    proxyURL, err := url.Parse("socks5://" + ti.BackendSocksHost)
    if err != nil {
        log.Printf("Instance %d ERROR: Failed to parse proxy URL %s: %v. HTTP client not updated.", ti.InstanceID, ti.BackendSocksHost, err)
        ti.httpClient = nil
        return
    }
    
    contextDialer, err := proxy.FromURL(proxyURL, &net.Dialer{Timeout: ti.appConfig.SocksTimeout})
    if err != nil {
        log.Printf("Instance %d ERROR: Failed to create proxy context dialer for %s: %v. HTTP client not updated.", ti.InstanceID, ti.BackendSocksHost, err)
        ti.httpClient = nil
        return
    }

    httpTransport := &http.Transport{
        DialContext: contextDialer.(proxy.ContextDialer).DialContext,
        MaxIdleConns:        10,
        IdleConnTimeout:     30 * time.Second,
        TLSHandshakeTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2: true,
    }
    ti.httpClient = &http.Client{
		Transport: httpTransport, 
		Timeout: ti.appConfig.SocksTimeout * 3,
	}
}

func (ti *Instance) ReinitializeHTTPClient() {
    ti.Mu.Lock()
    defer ti.Mu.Unlock()
    ti.initializeHTTPClientUnlocked()
    log.Printf("Instance %d: HTTP client explicitly re-initialized.", ti.InstanceID)
}

func (ti *Instance) GetHTTPClient() *http.Client {
	ti.Mu.Lock()
	defer ti.Mu.Unlock()
	if ti.httpClient == nil {
		ti.initializeHTTPClientUnlocked()
	}
	return ti.httpClient
}

// SetExternalIP updates the instance's last known external IP and check time.
func (ti *Instance) SetExternalIP(ip string) {
    ti.Mu.Lock()
    defer ti.Mu.Unlock()
    ti.ExternalIP = ip
    ti.LastIPCheck = time.Now()
}

// GetExternalIPInfo returns the last known external IP and check time.
// Note: This method is not currently used by other packages but is here for completeness.
func (ti *Instance) GetExternalIPInfo() (ip string, lastCheck time.Time) {
    ti.Mu.Lock()
    defer ti.Mu.Unlock()
    return ti.ExternalIP, ti.LastIPCheck
}


func firstNChars(s string, n int) string { 
    if len(s) > n {
        return s[:n] + "..."
    }
    return s
}
