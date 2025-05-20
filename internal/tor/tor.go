package tor // Correct package declaration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mrand "math/rand" // Alias for math/rand
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

const ifconfigURL = "https://ipinfo.io" // URL for checking external IP

// IpinfoIo struct for ipinfo.io response.
type IpinfoIo struct {
	IP       string `json:"ip"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Timezone string `json:"timezone"`
	Readme   string `json:"readme"`
}

// TorStruct holds information about a single Tor circuit managed by an external process.
type TorStruct struct {
	Cmd         *exec.Cmd    // Command for the running Tor process
	Port        string       // SOCKS port
	IPAddr      string       // External IP via this circuit
	Country     string       // Country of the exit node
	City        string       // City of the exit node
	Load        atomic.Int64 // For thread-safe load counting
	IsHealthy   bool         // Updated by HealthCheck
	LastChecked time.Time    // Last time this circuit was health-checked
	CreatedAt   time.Time    // Time when the circuit was successfully initialized
	DataDir     string       // Path to the Tor instance's data directory
	TorrcPath   string       // Path to the Tor instance's torrc file
}

// HealthStatus represents the health of a single circuit after a check.
// Defined here as it's closely related to TorStruct and HealthCheck function in this package.
type HealthStatus struct {
	CircuitIdentifier string // e.g., Port or IPAddr for identification
	IsHealthy         bool
	Error             error     // Error encountered during check, if any
	CheckedAt         time.Time // Time of this specific check
	OriginalPort      string
	OriginalIPAddr    string
	OriginalCountry   string
}


// IncrementLoad safely increments the load count.
func (p *TorStruct) IncrementLoad() {
	p.Load.Add(1)
}

// GetLoad safely retrieves the current load count.
func (p *TorStruct) GetLoad() int64 {
	return p.Load.Load()
}

// torInitResult is used to pass results from InitTor goroutines.
type torInitResult struct {
	tor TorStruct
	err error
}

// InitTor initializes 'n' Tor circuits by launching external Tor processes.
// currentPortUsage is an atomic counter for assigning ports.
// mathRand is a *mrand.Rand seeded in the main package.
// mathRandMutex protects access to mathRand.
// torgoInstanceBasePath is the base directory where instance data will be stored.
func InitTor(
	ctx context.Context,
	n int,
	listenHost, torExecutablePath, baseTorrcPath, torgoInstanceBasePath, torExitNodes string,
	circuitRenewInterval int,
	originalIPInfo IpinfoIo,
	currentPortUsage *atomic.Int32, 
	mathRand *mrand.Rand, 
	mathRandMutex *sync.Mutex, 
) ([]TorStruct, error) {
	var torCircuits []TorStruct
	results := make(chan torInitResult, n)
	var wg sync.WaitGroup

	staggerValues := make([]int, n)
	if circuitRenewInterval > 0 {
		mathRandMutex.Lock() 
		for i := 0; i < n; i++ {
			staggerValues[i] = mathRand.Intn(60) 
		}
		mathRandMutex.Unlock()
	}

	if err := os.MkdirAll(torgoInstanceBasePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create torgo instance base directory %s: %w", torgoInstanceBasePath, err)
	}
	log.Printf("INFO: [tor] Using base directory for Torgo's Tor instances: %s", torgoInstanceBasePath)


	for i := 0; i < n; i++ {
		wg.Add(1)
		portNum := currentPortUsage.Add(1) -1 
		portStr := strconv.Itoa(int(portNum))
		staggerSeconds := staggerValues[i]

		go func(pStr string, currentStaggerSeconds int) {
			defer wg.Done()
			procCtx, cancelProcCtx := context.WithCancel(ctx)
			defer cancelProcCtx()

			instanceDataDir := filepath.Join(torgoInstanceBasePath, fmt.Sprintf("tor_instance_%s_%d", pStr, time.Now().UnixNano()))
			if err := os.MkdirAll(instanceDataDir, 0700); err != nil {
				log.Printf("ERROR: [tor] Failed to create data directory for Tor on port %s: %v", pStr, err)
				results <- torInitResult{err: fmt.Errorf("create data dir for port %s: %w", pStr, err)}
				return
			}

			instanceTorrcPath := filepath.Join(instanceDataDir, "torrc")
			torrcLines := []string{
				fmt.Sprintf("SOCKSPort %s:%s", listenHost, pStr), 
				fmt.Sprintf("DataDirectory %s", instanceDataDir),
				"Log notice stdout", "AvoidDiskWrites 1", "ControlPort 0", "CookieAuthentication 0",
			}

			actualRenewIPVal := circuitRenewInterval + currentStaggerSeconds
			if actualRenewIPVal > 0 {
				torrcLines = append(torrcLines, fmt.Sprintf("MaxCircuitDirtiness %d", actualRenewIPVal))
			}

			if torExitNodes != "" {
				torrcLines = append(torrcLines, "StrictNodes 1")
				formattedExitNodes := []string{}
				for _, v := range strings.Split(torExitNodes, ",") {
					node := strings.TrimSpace(v)
					if !strings.HasPrefix(node, "{") || !strings.HasSuffix(node, "}") { node = fmt.Sprintf("{%s}", node) }
					formattedExitNodes = append(formattedExitNodes, node)
				}
				torrcLines = append(torrcLines, fmt.Sprintf("ExitNodes %s", strings.Join(formattedExitNodes, ",")))
			}

			if baseTorrcPath != "" {
				if _, errStat := os.Stat(baseTorrcPath); !os.IsNotExist(errStat) {
					baseContent, errRead := os.ReadFile(baseTorrcPath)
					if errRead != nil { log.Printf("WARN: [tor] Failed to read baseTorrcPath %s: %v.", baseTorrcPath, errRead)
					} else {
						scanner := bufio.NewScanner(strings.NewReader(string(baseContent)))
						for scanner.Scan() {
							line := strings.TrimSpace(scanner.Text())
							if line == "" || strings.HasPrefix(line, "#") { continue }
							fields := strings.Fields(line)
							if len(fields) > 0 {
								optionKey := strings.ToLower(fields[0])
								if optionKey == "sockport" || optionKey == "socksport" || optionKey == "datadirectory" {
									log.Printf("INFO: [tor] Skipping option '%s' from baseTorrc for port %s.", fields[0], pStr)
									continue
								}
								torrcLines = append(torrcLines, line)
							}
						}
						if errScan := scanner.Err(); errScan != nil { log.Printf("WARN: [tor] Error scanning baseTorrcPath %s: %v.", baseTorrcPath, errScan)
						} else { log.Printf("INFO: [tor] Merged settings from baseTorrcPath %s for port %s", baseTorrcPath, pStr) }
					}
				} else { log.Printf("INFO: [tor] Base torrc file %s not found, skipping merge.", baseTorrcPath) }
			}

			finalTorrcContent := strings.Join(torrcLines, "\n")
			if err := os.WriteFile(instanceTorrcPath, []byte(finalTorrcContent), 0600); err != nil {
				log.Printf("ERROR: [tor] Failed to write torrc for port %s: %v", pStr, err)
				results <- torInitResult{err: fmt.Errorf("write torrc for port %s: %w", pStr, err)}; os.RemoveAll(instanceDataDir); return
			}
			log.Printf("INFO: [tor] Generated torrc for port %s: %s", pStr, instanceTorrcPath)

			cmd := exec.CommandContext(procCtx, torExecutablePath, "-f", instanceTorrcPath)
			
			stdoutPipe, err := cmd.StdoutPipe(); if err != nil {
				log.Printf("ERROR: [tor] StdoutPipe failed for Tor on port %s: %v", pStr, err)
				results <- torInitResult{err: err}; os.RemoveAll(instanceDataDir); return
			}
			if err := cmd.Start(); err != nil {
				log.Printf("ERROR: [tor] Failed to start Tor process for port %s: %v", pStr, err)
				results <- torInitResult{err: fmt.Errorf("start Tor process for port %s: %w", pStr, err)}; os.RemoveAll(instanceDataDir); return
			}
			log.Printf("INFO: [tor] Tor process started for port %s (PID: %d), DataDir: %s, MaxCircuitDirtiness: %ds", pStr, cmd.Process.Pid, instanceDataDir, actualRenewIPVal)

			bootstrapped := make(chan bool); go func() {
				scanner := bufio.NewScanner(stdoutPipe)
				for scanner.Scan() {
					line := scanner.Text()
					if strings.Contains(line, "Bootstrapped 100%") || strings.Contains(line, "Opened Socks listener on") {
						log.Printf("INFO: [tor] Tor on port %s bootstrapped.", pStr); bootstrapped <- true; return
					}
				}
				if err := scanner.Err(); err != nil { log.Printf("ERROR: [tor] Error reading Tor stdout for port %s: %v", pStr, err) }
				log.Printf("WARN: [tor] Tor on port %s stdout pipe closed before bootstrap.", pStr); bootstrapped <- false 
			}()

			bootstrapTimeout := 2 * time.Minute; select {
			case success := <-bootstrapped:
				if !success {
					log.Printf("ERROR: [tor] Tor on port %s failed to bootstrap.", pStr); cmd.Process.Kill(); cmd.Wait()         
					results <- torInitResult{err: fmt.Errorf("Tor on port %s failed to bootstrap", pStr)}; os.RemoveAll(instanceDataDir); return
				}
			case <-time.After(bootstrapTimeout): 
				log.Printf("ERROR: [tor] Timeout (%v) bootstrapping Tor on port %s.", bootstrapTimeout, pStr); cmd.Process.Kill(); cmd.Wait()
				results <- torInitResult{err: fmt.Errorf("timeout bootstrapping Tor on port %s", pStr)}; os.RemoveAll(instanceDataDir); return
			}
			time.Sleep(1 * time.Second) 

			dialCheckCtx, dialCheckCancel := context.WithTimeout(ctx, 10*time.Second); defer dialCheckCancel()
			conn, err := (&net.Dialer{}).DialContext(dialCheckCtx, "tcp", listenHost+":"+pStr) 
			if err != nil {
				log.Printf("ERROR: [tor] SOCKS port %s connect check failed: %v", pStr, err); cmd.Process.Kill(); cmd.Wait()
				results <- torInitResult{err: fmt.Errorf("SOCKS port %s connect check: %w", pStr, err)}; os.RemoveAll(instanceDataDir); return
			}
			conn.Close()

			dialCtx, curlCancel := context.WithTimeout(ctx, 30*time.Second); defer curlCancel()
			socksDialer, err := proxy.SOCKS5("tcp", listenHost+":"+pStr, nil, &net.Dialer{Timeout: 10 * time.Second}) 
			if err != nil { 
				log.Printf("ERROR: [tor] SOCKS5 dialer (post-bootstrap) for port %s failed: %v", pStr, err); cmd.Process.Kill(); cmd.Wait()
				results <- torInitResult{err: fmt.Errorf("proxy.SOCKS5 (post-bootstrap) on port %s: %w", pStr, err)}; os.RemoveAll(instanceDataDir); return
			}
			tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) { return socksDialer.Dial(network, addr) }}
			httpClient := &http.Client{Transport: tr, Timeout: 20 * time.Second}
			body, _, err := CurlWithContext(dialCtx, httpClient, ifconfigURL)
			if err != nil {
				log.Printf("ERROR: [tor] Curl (post-bootstrap) for port %s failed: %v", pStr, err); cmd.Process.Kill(); cmd.Wait()
				results <- torInitResult{err: fmt.Errorf("Curl (post-bootstrap) on port %s: %w", pStr, err)}; os.RemoveAll(instanceDataDir); return
			}
			var ipInfo IpinfoIo
			if err := json.Unmarshal(body, &ipInfo); err != nil {
				log.Printf("ERROR: [tor] Unmarshal IP (post-bootstrap) for port %s failed: %v", pStr, err); cmd.Process.Kill(); cmd.Wait()
				results <- torInitResult{err: fmt.Errorf("json.Unmarshal (post-bootstrap) on port %s: %w", pStr, err)}; os.RemoveAll(instanceDataDir); return
			}

			log.Printf("INFO: [tor] Circuit test OK (post-bootstrap). RealIP: %s, TorIP: %s, Country: %s, Port: %s",
				originalIPInfo.IP, ipInfo.IP, ipInfo.Country, pStr)

			results <- torInitResult{tor: TorStruct{
				Cmd: cmd, Port: pStr, Country: ipInfo.Country, IPAddr: ipInfo.IP, City: ipInfo.City,
				IsHealthy: true, LastChecked: time.Now(), CreatedAt: time.Now(),
				DataDir: instanceDataDir, TorrcPath: instanceTorrcPath,
			}}
		}(portStr, staggerSeconds)
	}

	wg.Wait(); close(results)
	var initErrors []string
	for res := range results {
		if res.err != nil { initErrors = append(initErrors, res.err.Error())
		} else { torCircuits = append(torCircuits, res.tor) }
	}
	
	// currentPortUsage is managed atomically by the goroutines.

	if len(torCircuits) == 0 && n > 0 {
		return nil, fmt.Errorf("failed to initialize any Tor circuits. Errors: %s", strings.Join(initErrors, "; "))
	}
	if len(initErrors) > 0 {
		log.Printf("WARN: [tor] Some Tor circuits failed to initialize: %s", strings.Join(initErrors, "; "))
	}
	return torCircuits, nil
}

// CurlTor performs a GET request through a specific Tor circuit.
func CurlTor(ctx context.Context, urlStr string, p TorStruct, listenHost string) (*http.Response, error) {
	socksDialer, err := proxy.SOCKS5("tcp", listenHost+":"+p.Port, nil, &net.Dialer{ Timeout: 10 * time.Second })
	if err != nil { return nil, fmt.Errorf("CurlTor: SOCKS5 dialer for port %s: %w", p.Port, err) }
	tr := &http.Transport{ DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) { return socksDialer.Dial(network, addr) } }
	myClient := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil { return nil, fmt.Errorf("CurlTor: creating request: %w", err) }
	res, err := myClient.Do(req); if err != nil { return nil, fmt.Errorf("CurlTor: performing request: %w", err) }
	return res, nil
}

// TortoMap prepares a slice of maps of TorStructs for API responses.
func TortoMap(p []TorStruct, listenHost string) []map[string]interface{} {
	apiCircuits := make([]map[string]interface{}, 0, len(p))
	for _, v := range p {
		apiCircuits = append(apiCircuits, map[string]interface{}{
			"IPAddress":   v.IPAddr, "Socks5": listenHost + ":" + v.Port, "Country": v.Country,
			"City": v.City, "Load": v.GetLoad(), "IsHealthy":   v.IsHealthy,
			"LastChecked": v.LastChecked.Format(time.RFC3339Nano),
			"CreatedAt":   v.CreatedAt.Format(time.RFC3339Nano),
			"Port": v.Port, "DataDir": v.DataDir, 
		})
	}
	return apiCircuits
}

// DeleteCircuit stops the Tor process and cleans up its data directory.
func (p *TorStruct) DeleteCircuit() {
	if p.Cmd != nil && p.Cmd.Process != nil {
		log.Printf("INFO: [tor] Stopping Tor process for port %s (PID: %d)", p.Port, p.Cmd.Process.Pid)
		if err := p.Cmd.Process.Signal(os.Interrupt); err != nil { 
			log.Printf("WARN: [tor] SIGINT to Tor port %s failed: %v. Killing.", p.Port, err)
			if killErr := p.Cmd.Process.Kill(); killErr != nil { log.Printf("ERROR: [tor] Kill Tor port %s failed: %v", p.Port, killErr) }
		}
		waitDone := make(chan error, 1); go func() { waitDone <- p.Cmd.Wait() }()
		select {
		case err := <-waitDone:
			if err != nil && !strings.Contains(err.Error(), "exit status") && !strings.Contains(err.Error(), "signal:") && !strings.Contains(err.Error(), "already finished") {
				log.Printf("WARN: [tor] Wait Tor port %s error: %v", p.Port, err)
			} else { log.Printf("INFO: [tor] Tor port %s exited.", p.Port) }
		case <-time.After(10 * time.Second): 
			log.Printf("WARN: [tor] Timeout waiting for Tor port %s. Killing.", p.Port)
			if p.Cmd.ProcessState == nil || !p.Cmd.ProcessState.Exited() { p.Cmd.Process.Kill() }
		}
	} else { log.Printf("INFO: [tor] No active Tor process for port %s.", p.Port) }
	if p.DataDir != "" {
		log.Printf("INFO: [tor] Removing DataDir for Tor port %s: %s", p.Port, p.DataDir)
		if err := os.RemoveAll(p.DataDir); err != nil { log.Printf("ERROR: [tor] Failed to remove DataDir %s: %v", p.DataDir, err) }
	}
}

// RemoveTorList removes a TorStruct from a slice by index.
func RemoveTorList(s []TorStruct, index int) []TorStruct {
	if index < 0 || index >= len(s) { return s }
	return append(s[:index], s[index+1:]...)
}

var (
	roundRobinCounter = 0            
	roundRobinMutex   sync.Mutex 
)

// GetTorLB gets one Tor circuit using Round Robin from healthy circuits.
func GetTorLB(circuits []TorStruct) *TorStruct {
	healthyCircuits := make([]*TorStruct, 0, len(circuits))
    for i := range circuits { if circuits[i].IsHealthy { healthyCircuits = append(healthyCircuits, &circuits[i]) } }
	if len(healthyCircuits) == 0 { return nil }

	roundRobinMutex.Lock()
	if roundRobinCounter >= len(healthyCircuits) { roundRobinCounter = 0 }
	if len(healthyCircuits) == 0 { roundRobinMutex.Unlock(); return nil } 
	selected := healthyCircuits[roundRobinCounter]
	roundRobinCounter = (roundRobinCounter + 1) % len(healthyCircuits)
	roundRobinMutex.Unlock()
	return selected
}

// GetTorLBWeight selects the healthiest Tor circuit with the least current load.
func GetTorLBWeight(circuits []TorStruct) *TorStruct {
	var selected *TorStruct = nil
	var minLoad int64 = -1

	for i := range circuits {
		if !circuits[i].IsHealthy { continue }
		currentLoad := circuits[i].GetLoad()
		if selected == nil || currentLoad < minLoad {
			minLoad = currentLoad
			selected = &circuits[i]
		}
	}
	if selected == nil { log.Printf("WARN: [tor] GetTorLBWeight: No healthy circuits."); }
	return selected
}

// GetTorLBRandom randomly selects a healthy Tor circuit.
func GetTorLBRandom(circuits []TorStruct, mathRand *mrand.Rand, mathRandMutex *sync.Mutex) *TorStruct {
    healthyCircuits := make([]*TorStruct, 0, len(circuits))
    for i := range circuits { if circuits[i].IsHealthy { healthyCircuits = append(healthyCircuits, &circuits[i]) } }
    if len(healthyCircuits) == 0 { log.Printf("WARN: [tor] GetTorLBRandom: No healthy circuits."); return nil }
    
	mathRandMutex.Lock()
    idx := mathRand.Intn(len(healthyCircuits))
	mathRandMutex.Unlock()
    return healthyCircuits[idx]
}

// CurlWithContext performs a GET request using the provided HTTP client and context.
func CurlWithContext(ctx context.Context, c *http.Client, urlStr string) ([]byte, *http.Response, error) {
	if urlStr == "" { urlStr = ifconfigURL }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil { return nil, nil, fmt.Errorf("creating request for %s: %w", urlStr, err) }
	res, err := c.Do(req)
	if err != nil { return nil, nil, fmt.Errorf("performing request to %s: %w", urlStr, err) }
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil { return nil, res, fmt.Errorf("reading response body from %s: %w", urlStr, err) }
	return body, res, nil
}
