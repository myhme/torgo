package adblock // Correct package declaration

import (
	"bufio"
	"context"
	"fmt"
	// "io" // Removed unused import
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// UpdateAdblockListsAndReloadDnsmasq fetches adblock lists from the provided URLs,
// merges them into the specified hostsFilePath, and signals dnsmasq to reload.
// It uses a mutex to prevent concurrent updates.
func UpdateAdblockListsAndReloadDnsmasq(
	ctx context.Context,
	adblockURLs []string, // Current list of URLs to fetch
	hostsFilePath string, // Path to write the merged hosts file
	updateInProgressMutex *sync.Mutex, // Mutex to ensure single update at a time
) (int, time.Time, error) {

	updateInProgressMutex.Lock()
	defer updateInProgressMutex.Unlock()

	log.Println("INFO: [adblock] Starting adblock list update...")
	startTime := time.Now()

	if len(adblockURLs) == 0 {
		log.Println("INFO: [adblock] No adblock URLs configured. Clearing adblock hosts file.")
		minimalContent := "0.0.0.0 localhost\n127.0.0.1 localhost\n::1 localhost\n# No adblock lists configured\n"
		if err := os.WriteFile(hostsFilePath, []byte(minimalContent), 0644); err != nil {
			log.Printf("ERROR: [adblock] Failed to clear adblock hosts file %s: %v", hostsFilePath, err)
			return 0, startTime, err
		}
		SignalDnsmasqToReload(ctx)
		return 0, startTime, nil
	}

	var allHostsContent strings.Builder
	allHostsContent.WriteString("0.0.0.0 localhost\n")
	allHostsContent.WriteString("127.0.0.1 localhost\n")
	allHostsContent.WriteString("::1 localhost\n")

	httpClient := &http.Client{Timeout: 45 * time.Second}
	uniqueBlockedDomains := make(map[string]bool)
	var downloadErrors []string

	for _, urlStr := range adblockURLs {
		if strings.TrimSpace(urlStr) == "" {
			continue
		}
		log.Printf("INFO: [adblock] Downloading: %s", urlStr)
		reqCtx, cancelReq := context.WithTimeout(ctx, 90*time.Second)

		req, err := http.NewRequestWithContext(reqCtx, "GET", urlStr, nil)
		if err != nil {
			log.Printf("WARN: [adblock] Failed to create request for %s: %v", urlStr, err)
			downloadErrors = append(downloadErrors, fmt.Sprintf("create_request_%s: %v", urlStr, err))
			cancelReq()
			continue
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			log.Printf("WARN: [adblock] Failed to download from %s: %v", urlStr, err)
			downloadErrors = append(downloadErrors, fmt.Sprintf("download_%s: %v", urlStr, err))
			cancelReq()
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("WARN: [adblock] Download failed from %s, status: %s", urlStr, resp.Status)
			downloadErrors = append(downloadErrors, fmt.Sprintf("status_%s: %s", urlStr, resp.Status))
			resp.Body.Close()
			cancelReq()
			continue
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ip := parts[0]
				domain := strings.ToLower(parts[1])
				if (ip == "0.0.0.0" || ip == "127.0.0.1") && domain != "localhost" && !strings.Contains(domain, "#") {
					if !uniqueBlockedDomains[domain] {
						fmt.Fprintf(&allHostsContent, "0.0.0.0 %s\n", domain)
						uniqueBlockedDomains[domain] = true
					}
				}
			}
		}
		resp.Body.Close()
		cancelReq()
		if err := scanner.Err(); err != nil {
			log.Printf("WARN: [adblock] Error reading adblock list from %s: %v", urlStr, err)
			downloadErrors = append(downloadErrors, fmt.Sprintf("read_body_%s: %v", urlStr, err))
		}
	}

	if err := os.MkdirAll(filepath.Dir(hostsFilePath), 0755); err != nil {
		log.Printf("ERROR: [adblock] Failed to create directory for %s: %v", hostsFilePath, err)
		return 0, startTime, err
	}

	if err := os.WriteFile(hostsFilePath, []byte(allHostsContent.String()), 0644); err != nil {
		log.Printf("ERROR: [adblock] Failed to write merged adblock hosts file %s: %v", hostsFilePath, err)
		return 0, startTime, err
	}
	log.Printf("INFO: [adblock] Merged adblock list written to %s with %d unique domains.", hostsFilePath, len(uniqueBlockedDomains))

	SignalDnsmasqToReload(ctx)

	if len(downloadErrors) > 0 {
		return len(uniqueBlockedDomains), startTime, fmt.Errorf("encountered errors during adblock list download: %s", strings.Join(downloadErrors, "; "))
	}

	return len(uniqueBlockedDomains), startTime, nil
}

// SignalDnsmasqToReload sends a SIGHUP signal to dnsmasq to reload its configuration.
func SignalDnsmasqToReload(ctx context.Context) {
	log.Println("INFO: [adblock] Signaling dnsmasq to reload configuration...")
	cmdCtx, cancelCmd := context.WithTimeout(ctx, 10*time.Second)
	defer cancelCmd()

	// Try pkill first
	cmdPkill := exec.CommandContext(cmdCtx, "pkill", "-HUP", "dnsmasq")
	output, err := cmdPkill.CombinedOutput()

	if err != nil {
		log.Printf("WARN: [adblock] Failed to signal dnsmasq with pkill (pkill -HUP dnsmasq). Error: %v. Output: %s. Trying killall.", err, string(output))
		// Fallback to killall
		cmdKillall := exec.CommandContext(cmdCtx, "killall", "-HUP", "dnsmasq") // Corrected: use cmdKillall
		output, err = cmdKillall.CombinedOutput() // Corrected: use cmdKillall
		if err != nil {
			log.Printf("WARN: [adblock] Failed to signal dnsmasq with killall (killall -HUP dnsmasq) as well. Error: %v. Output: %s.", err, string(output))
		} else {
			log.Println("INFO: [adblock] Signal HUP sent to dnsmasq successfully via killall.")
		}
	} else {
		log.Println("INFO: [adblock] Signal HUP sent to dnsmasq successfully via pkill.")
	}
}
