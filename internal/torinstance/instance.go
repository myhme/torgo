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
	"torgo/internal/config" // Assuming your module path is 'torgo'
)

// Instance represents a single backend Tor process and its state.
type Instance struct {
	InstanceID       int
	ControlHost      string // e.g., "127.0.0.1:9161"
	BackendSocksHost string // e.g., "127.0.0.1:9051"
	BackendDNSHost   string // e.g., "127.0.0.1:9201" (Tor's actual DNS port)
	AuthCookiePath   string
	DataDir          string

	Mu                sync.Mutex // Exported Mutex
	httpClient        *http.Client // For IP checking via this specific Tor instance
	activeControlConn net.Conn
	controlCookieHex  string
	IsHealthy         bool // Exported for direct read by other packages (under instance lock)
	LastHealthCheck   time.Time // Exported

	appConfig *config.AppConfig // Reference to global app config
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

func (ti *Instance) loadAndCacheControlCookieUnlocked() error {
	// Assumes ti.Mu is locked
	if ti.controlCookieHex != "" {
		return nil
	}
	cookieBytes, err := os.ReadFile(ti.AuthCookiePath)
	if err != nil {
		return fmt.Errorf("instance %d: failed to read cookie %s: %w", ti.InstanceID, ti.AuthCookiePath, err)
	}
	ti.controlCookieHex = hex.EncodeToString(cookieBytes)
	return nil
}

func (ti *Instance) connectToTorControlUnlocked() (net.Conn, *bufio.Reader, error) {
	// Assumes ti.Mu is locked
	if err := ti.loadAndCacheControlCookieUnlocked(); err != nil {
		return nil, nil, err
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

	if !strings.HasPrefix(statusLine, "250 OK") {
		conn.Close()
		return nil, nil, fmt.Errorf("instance %d: tor control port authentication failed: %s", ti.InstanceID, strings.TrimSpace(statusLine))
	}
	ti.activeControlConn = conn
	return conn, reader, nil
}

// CloseControlConnUnlocked closes the active control connection. Assumes ti.Mu is locked.
func (ti *Instance) CloseControlConnUnlocked() {
	if ti.activeControlConn != nil {
		ti.activeControlConn.Close()
		ti.activeControlConn = nil
	}
}

// SendTorCommand sends a command to this Tor instance's control port.
func (ti *Instance) SendTorCommand(command string) (string, error) {
	ti.Mu.Lock() 
	defer ti.Mu.Unlock()

	var conn net.Conn
	var reader *bufio.Reader
	var err error

	if ti.activeControlConn != nil {
		conn = ti.activeControlConn
		reader = bufio.NewReader(conn) 
	} else {
		conn, reader, err = ti.connectToTorControlUnlocked()
		if err != nil {
			return "", fmt.Errorf("instance %d SendTorCommand: connection phase failed: %w", ti.InstanceID, err)
		}
	}

	conn.SetWriteDeadline(time.Now().Add(ti.appConfig.SocksTimeout)) 
	if _, errWrite := conn.Write([]byte(command + "\r\n")); errWrite != nil {
		conn.SetWriteDeadline(time.Time{})  
		ti.CloseControlConnUnlocked()      
		log.Printf("Instance %d: Write failed for command '%s' (%v), connection closed.", ti.InstanceID, command, errWrite)
		return "", fmt.Errorf("instance %d: write failed for command '%s': %w", ti.InstanceID, command, errWrite)
	}
	conn.SetWriteDeadline(time.Time{}) 

	var responseBuffer bytes.Buffer
	isMultiLine := strings.HasPrefix(command, "GETINFO")
	
	readDeadlineDuration := 10 * time.Second 
	if isMultiLine {
		readDeadlineDuration = 20 * time.Second 
	}
	conn.SetReadDeadline(time.Now().Add(readDeadlineDuration))

	for {
		line, errRead := reader.ReadString('\n')
		if errRead != nil {
			conn.SetReadDeadline(time.Time{}) 
			ti.CloseControlConnUnlocked()    
			// log.Printf("Instance %d: Read failed for command '%s' (%v), connection closed. Partial response: '%s'", ti.InstanceID, command, errRead, responseBuffer.String())
			return responseBuffer.String(), fmt.Errorf("instance %d: failed to read full response for '%s': %w. Partial: '%s'", ti.InstanceID, command, errRead, responseBuffer.String())
		}
		responseBuffer.WriteString(line)
		trimmedLine := strings.TrimSpace(line)
		
		if strings.HasPrefix(trimmedLine, "250 OK") { break } 
		if strings.HasPrefix(trimmedLine, "250 ") && !strings.HasPrefix(trimmedLine, "250-") && !isMultiLine { break } 
		if strings.HasPrefix(trimmedLine, "5") { 
			// log.Printf("Instance %d: Received Tor error response for command '%s': %s", ti.InstanceID, command, trimmedLine)
			break 
		}
	}
	conn.SetReadDeadline(time.Time{}) 
	return strings.TrimSpace(responseBuffer.String()), nil
}

// CheckHealth updates the IsHealthy status of the instance.
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
	var errMsg string

	select {
	case <-healthCtx.Done():
		errMsg = fmt.Sprintf("timed out for control host %s", ti.ControlHost)
		log.Printf("Instance %d: Health check %s", ti.InstanceID, errMsg)
	case res := <-ch:
		// Log the raw response for debugging if it's not what we expect
		// if !strings.Contains(res.response, "PROGRESS=100 TAG=done") || res.err != nil {
		// 	log.Printf("Instance %d: Health check raw response: '%s', error: %v", ti.InstanceID, res.response, res.err)
		// }

		// The key parts of a successful bootstrap are "PROGRESS=100" and "TAG=done".
		// The full key "status/bootstrap-phase=" should also be present.
		// Example successful response from Tor: "250-status/bootstrap-phase=PROGRESS=100 TAG=done SUMMARY=\"Done\"\n250 OK"
		// After SendTorCommand processing, res.response might be "status/bootstrap-phase=PROGRESS=100 TAG=done SUMMARY=\"Done\"\n250 OK"
		// or just "PROGRESS=100 TAG=done SUMMARY=\"Done\"" if Tor replies with a single line for some GETINFO.
		
		if res.err == nil &&
		   strings.Contains(res.response, "PROGRESS=100") &&
		   strings.Contains(res.response, "TAG=done") &&
		   (strings.Contains(res.response, "status/bootstrap-phase=") || strings.HasPrefix(res.response, "PROGRESS=100")) { // Be a bit flexible on the key prefix
			isCurrentlyHealthy = true
		} else {
			if res.err != nil {
				errMsg = fmt.Sprintf("error: %v", res.err)
			} else { 
				logMsg := res.response
				if len(logMsg) > 150 { logMsg = logMsg[:150] + "..."} 
				errMsg = fmt.Sprintf("unexpected bootstrap phase or content: '%s'", logMsg)
			}
			log.Printf("Instance %d: Health check failed for control host %s (%s)", ti.InstanceID, ti.ControlHost, errMsg)
		}
	}

	ti.Mu.Lock()
	if ti.IsHealthy != isCurrentlyHealthy {
		log.Printf("Instance %d: Health status changed to %v (was %v). Last check reason: %s", ti.InstanceID, isCurrentlyHealthy, ti.IsHealthy, errMsg)
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
