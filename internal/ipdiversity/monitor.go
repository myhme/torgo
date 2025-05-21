package ipdiversity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"torgo/internal/config"
	"torgo/internal/torinstance"
)

// MonitorIPDiversity periodically checks for IP similarity and triggers rotations.
func MonitorIPDiversity(ctx context.Context, instances []*torinstance.Instance, appCfg *config.AppConfig) {
	if appCfg.MinInstancesForIPDiversityCheck <= 0 || len(instances) < appCfg.MinInstancesForIPDiversityCheck {
		log.Printf("IP Diversity Monitor: Not running, configured minimum instances (%d) not met or disabled.", appCfg.MinInstancesForIPDiversityCheck)
		return
	}

	log.Printf("IP Diversity Monitor started. Check interval: %v, Rotation cooldown: %v", appCfg.IPDiversityCheckInterval, appCfg.IPDiversityRotationCooldown)
	ticker := time.NewTicker(appCfg.IPDiversityCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// log.Println("IP Diversity Monitor: Running check...")
			checkForSimilarIPsAndRotate(instances, appCfg)
		case <-ctx.Done():
			log.Println("IP Diversity Monitor: Stopping due to context cancellation.")
			return
		}
	}
}

func checkForSimilarIPsAndRotate(instances []*torinstance.Instance, appCfg *config.AppConfig) {
	if len(instances) < appCfg.MinInstancesForIPDiversityCheck {
		return // Not enough instances to warrant a check
	}

	currentIPs := make(map[int]string) // Map instance ID to its IP
	healthyInstancesForCheck := make([]*torinstance.Instance, 0)

	// Step 1: Fetch current IPs for all healthy instances
	for _, instance := range instances {
		instance.Mu.Lock()
		isHealthy := instance.IsHealthy
		instance.Mu.Unlock()

		if !isHealthy {
			continue // Skip unhealthy instances
		}
		healthyInstancesForCheck = append(healthyInstancesForCheck, instance)

		// Use the instance's dedicated HTTP client to fetch its IP
		client := instance.GetHTTPClient()
		if client == nil {
			// log.Printf("IP Diversity: Instance %d: HTTP client not ready, skipping IP check.", instance.InstanceID)
			continue
		}

		reqCtx, cancel := context.WithTimeout(context.Background(), appCfg.SocksTimeout*2) // Use a background context for this internal check
		
		httpReq, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, appCfg.IPCheckURL, nil)
		resp, err := client.Do(httpReq)
		cancel() // Release context resources early

		if err != nil {
			// log.Printf("IP Diversity: Instance %d: Error fetching IP: %v", instance.InstanceID, err)
			continue
		}
		
		body, errRead := io.ReadAll(resp.Body)
		resp.Body.Close()
		if errRead != nil {
			// log.Printf("IP Diversity: Instance %d: Error reading IP response body: %v", instance.InstanceID, errRead)
			continue
		}

		var ipJsonResponse struct { IP string `json:"IP"`	}
		var plainTextIP string

		if errJson := json.Unmarshal(body, &ipJsonResponse); errJson == nil && ipJsonResponse.IP != "" {
			currentIPs[instance.InstanceID] = ipJsonResponse.IP
			instance.SetExternalIP(ipJsonResponse.IP)
		} else {
			trimmedBody := strings.TrimSpace(string(body))
			if net.ParseIP(trimmedBody) != nil {
				currentIPs[instance.InstanceID] = trimmedBody
				instance.SetExternalIP(trimmedBody)
				plainTextIP = trimmedBody
			} else {
				// log.Printf("IP Diversity: Instance %d: IP response not valid JSON with IP or plain IP: %s", instance.InstanceID, firstNChars(trimmedBody, 30))
			}
		}
		if plainTextIP == "" && ipJsonResponse.IP == "" {
			// log.Printf("IP Diversity: Instance %d: Could not determine IP.", instance.InstanceID)
		}
	}

	if len(currentIPs) < appCfg.MinInstancesForIPDiversityCheck {
		// log.Printf("IP Diversity: Not enough IPs fetched (%d) to perform similarity check (min: %d).", len(currentIPs), appCfg.MinInstancesForIPDiversityCheck)
		return
	}

	// Step 2: Group IPs by /24 subnet
	subnets := make(map[string][]*torinstance.Instance) // Map subnet prefix to list of instances
	for instanceID, ipStr := range currentIPs {
		parsedIP := net.ParseIP(ipStr)
		if parsedIP == nil || parsedIP.To4() == nil {
			// log.Printf("IP Diversity: Instance %d: Invalid or non-IPv4 IP '%s', skipping.", instanceID, ipStr)
			continue
		}
		// Get /24 prefix (e.g., "1.2.3")
		subnetPrefix := fmt.Sprintf("%d.%d.%d", parsedIP.To4()[0], parsedIP.To4()[1], parsedIP.To4()[2])
		
		var instPtr *torinstance.Instance
		for _, inst := range healthyInstancesForCheck { // Find the instance pointer
			if inst.InstanceID == instanceID {
				instPtr = inst
				break
			}
		}
		if instPtr != nil {
			subnets[subnetPrefix] = append(subnets[subnetPrefix], instPtr)
		}
	}

	// Step 3: Find subnets with multiple instances and trigger rotation
	for subnet, instancesInSubnet := range subnets {
		if len(instancesInSubnet) >= 2 { // We need at least 2 to have similarity within our check
			log.Printf("IP Diversity: Subnet %s.0/24 has %d instances with similar IPs: %v", subnet, len(instancesInSubnet), getIDs(instancesInSubnet))

			// Select an instance to rotate from this group.
			// Prioritize one that hasn't been rotated by this mechanism recently.
			var instanceToRotate *torinstance.Instance = nil
			var oldestRotateTime time.Time

			for _, inst := range instancesInSubnet {
				inst.Mu.Lock()
				lastRot := inst.LastDiversityRotate
				inst.Mu.Unlock()

				if instanceToRotate == nil || lastRot.Before(oldestRotateTime) {
					// Check cooldown for this specific instance
					if time.Since(lastRot) > appCfg.IPDiversityRotationCooldown {
						instanceToRotate = inst
						oldestRotateTime = lastRot
					} else {
						// log.Printf("IP Diversity: Instance %d in subnet %s is in cooldown (last rotated %v ago). Skipping for now.", inst.InstanceID, subnet, time.Since(lastRot))
					}
				}
			}

			if instanceToRotate != nil {
				log.Printf("IP Diversity: Rotating instance %d (IP: %s) in subnet %s.0/24 due to IP similarity.", instanceToRotate.InstanceID, instanceToRotate.ExternalIP, subnet)
				_, err := instanceToRotate.SendTorCommand("SIGNAL NEWNYM")
				if err != nil {
					log.Printf("IP Diversity: Error sending NEWNYM to instance %d: %v", instanceToRotate.InstanceID, err)
				} else {
					instanceToRotate.Mu.Lock()
					instanceToRotate.LastDiversityRotate = time.Now()
					// Optionally clear its ExternalIP here so it's re-fetched sooner by WebUI or next check
					// instanceToRotate.ExternalIP = "" 
					instanceToRotate.Mu.Unlock()
					log.Printf("IP Diversity: NEWNYM signal sent to instance %d.", instanceToRotate.InstanceID)
					// After rotating one, we can break from this subnet check for this cycle
					// to give it time to get a new IP before checking again.
					// Or, continue and rotate another if multiple groups exist (less ideal).
					// For now, rotate one per identified similar group per check cycle.
				}
			} else {
				// log.Printf("IP Diversity: All instances in subnet %s.0/24 are in rotation cooldown.", subnet)
			}
		}
	}
}

func getIDs(instances []*torinstance.Instance) []int {
	ids := make([]int, len(instances))
	for i, inst := range instances {
		ids[i] = inst.InstanceID
	}
	return ids
}

func firstNChars(s string, n int) string { // Helper
    if len(s) > n {
        return s[:n] + "..."
    }
    return s
}
