package rotation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"torgo/internal/config"
	"torgo/internal/tor"
)

var ipDiversityCheckInProgress int32

func MonitorIPDiversity(ctx context.Context, instances []*tor.Instance, appCfg *config.AppConfig) {
	if appCfg.MinInstancesForIPDiversityCheck <= 0 || len(instances) < appCfg.MinInstancesForIPDiversityCheck || appCfg.IPDiversityCheckInterval <= 0 {
		return
	}
	log.Printf("IPDiversityMonitor: Started. Interval: %v, Cooldown: %v, MinInstances: %d",
		appCfg.IPDiversityCheckInterval, appCfg.IPDiversityRotationCooldown, appCfg.MinInstancesForIPDiversityCheck)
	ticker := time.NewTicker(appCfg.IPDiversityCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if atomic.CompareAndSwapInt32(&ipDiversityCheckInProgress, 0, 1) {
				go func() {
					defer atomic.StoreInt32(&ipDiversityCheckInProgress, 0)
					checkForSimilarIPsAndRotate(ctx, instances, appCfg)
				}()
			}
		case <-ctx.Done():
			log.Println("IPDiversityMonitor: Stopping.")
			return
		}
	}
}

func checkForSimilarIPsAndRotate(ctx context.Context, instances []*tor.Instance, appCfg *config.AppConfig) {
	if len(instances) < appCfg.MinInstancesForIPDiversityCheck { return }
	currentIPs := make(map[int]string)
	checkedInstances := make([]*tor.Instance, 0, len(instances))
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, instance := range instances {
		if !instance.IsCurrentlyHealthy() { continue }
		wg.Add(1)
		go func(inst *tor.Instance) {
			defer wg.Done()
			select { case <-ctx.Done(): return; default: }
			client := inst.GetHTTPClient()
			if client == nil { return }
			fetchCtx, cancel := context.WithTimeout(ctx, appCfg.SocksTimeout*2+5*time.Second)
			defer cancel()
			httpReq, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, appCfg.IPCheckURL, nil)
			if err != nil { return }
			resp, err := client.Do(httpReq)
			if err != nil { return }
			defer resp.Body.Close()
			body, errRead := io.ReadAll(resp.Body)
			if errRead != nil { return }
			var ipStr string
			var ipJsonResponse struct{ IP string `json:"IP"` }
			if errJson := json.Unmarshal(body, &ipJsonResponse); errJson == nil && ipJsonResponse.IP != "" {
				ipStr = ipJsonResponse.IP
			} else {
				trimmedBody := strings.TrimSpace(string(body))
				if net.ParseIP(trimmedBody) != nil { ipStr = trimmedBody } else { return }
			}
			if ipStr != "" {
				inst.SetExternalIP(ipStr, time.Now())
				mu.Lock()
				currentIPs[inst.InstanceID] = ipStr
				checkedInstances = append(checkedInstances, inst)
				mu.Unlock()
			}
		}(instance)
	}
	wg.Wait()
	mu.Lock()
	numCheckedWithIPs := len(checkedInstances)
	mu.Unlock()
	if numCheckedWithIPs < appCfg.MinInstancesForIPDiversityCheck { return }

	subnets := make(map[string][]*tor.Instance)
	mu.Lock()
	for _, inst := range checkedInstances {
		ipStr, ok := currentIPs[inst.InstanceID]
		if !ok || ipStr == "" { continue }
		parsedIP := net.ParseIP(ipStr)
		if parsedIP == nil { continue }
		var subnetPrefix string
		if parsedIP.To4() != nil {
			subnetPrefix = fmt.Sprintf("%d.%d.%d.0/24", parsedIP.To4()[0], parsedIP.To4()[1], parsedIP.To4()[2])
		} else if ip6 := parsedIP.To16(); ip6 != nil { // Basic IPv6 /48, adjust as needed
            subnetPrefix = fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x::/48", ip6[0], ip6[1], ip6[2], ip6[3], ip6[4], ip6[5])
        } else { continue }
		subnets[subnetPrefix] = append(subnets[subnetPrefix], inst)
	}
	mu.Unlock()

	for subnet, instancesInSubnet := range subnets {
		if len(instancesInSubnet) >= 2 {
			var instanceToRotate *tor.Instance
			var oldestDiversityRotateTimeForCandidate time.Time
			for _, inst := range instancesInSubnet {
				_, lastDiversityRot := inst.GetCircuitTimestamps()
				if time.Since(lastDiversityRot) > appCfg.IPDiversityRotationCooldown {
					if instanceToRotate == nil || lastDiversityRot.Before(oldestDiversityRotateTimeForCandidate) {
						instanceToRotate = inst
						oldestDiversityRotateTimeForCandidate = lastDiversityRot
					}
				}
			}
			if instanceToRotate != nil {
				currentIP, _, _ := instanceToRotate.GetExternalIPInfo()
				log.Printf("IPDiversityMonitor: Rotating instance %d (IP: %s) in subnet %s.", instanceToRotate.InstanceID, currentIP, subnet)
				_, err := instanceToRotate.SendTorCommand("SIGNAL NEWNYM")
				if err != nil {
					log.Printf("IPDiversityMonitor: Error NEWNYM for instance %d: %v", instanceToRotate.InstanceID, err)
				} else {
					instanceToRotate.UpdateLastDiversityRotate()
					instanceToRotate.SetExternalIP("", time.Time{})
					log.Printf("IPDiversityMonitor: NEWNYM sent to instance %d for IP diversity.", instanceToRotate.InstanceID)
					break // Process one conflicting subnet group per check cycle
				}
			}
		}
	}
}
