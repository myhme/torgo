package lb

import (
	"fmt"
	"log/slog" // Import slog
	"math/rand/v2" 
	"sync/atomic" 

	"torgo/internal/config"
	"torgo/internal/torinstance"
)

var roundRobinIndex uint32 

// GetNextHealthyInstance selects a healthy backend Tor instance based on the configured strategy.
func GetNextHealthyInstance(instances []*torinstance.Instance, appCfg *config.AppConfig) (*torinstance.Instance, error) {
	if len(instances) == 0 {
		return nil, fmt.Errorf("no backend Tor instances configured")
	}

	healthyInstances := make([]*torinstance.Instance, 0, len(instances))

	for _, instance := range instances {
		instance.Mu.Lock()
		isHealthy := instance.IsHealthy
		instance.Mu.Unlock()

		if isHealthy {
			healthyInstances = append(healthyInstances, instance)
		}
	}

	if len(healthyInstances) == 0 {
		return nil, fmt.Errorf("no healthy backend Tor instances available")
	}

	var selectedInstance *torinstance.Instance

	switch appCfg.LoadBalancingStrategy {
	case "round-robin":
		currentIndex := atomic.AddUint32(&roundRobinIndex, 1) - 1
		selectedInstance = healthyInstances[currentIndex%uint32(len(healthyInstances))]
		slog.Debug("LB (RoundRobin): Selected Tor instance.", "instance_id", selectedInstance.InstanceID, "index", currentIndex)

	case "least-connections-proxy":
		var minConns int32 = -1 
		for _, inst := range healthyInstances {
			currentConns := inst.GetActiveProxyConnections()
			if selectedInstance == nil || currentConns < minConns {
				minConns = currentConns
				selectedInstance = inst
			}
		}
		if selectedInstance != nil { // Check if an instance was actually selected
			slog.Debug("LB (LeastConns): Selected Tor instance.", "instance_id", selectedInstance.InstanceID, "active_connections", minConns)
		} else {
			// This should not happen if healthyInstances is not empty
			slog.Error("LB (LeastConns): No instance selected despite healthy options. This is unexpected.")
			// Fallback to random if something went wrong with selection logic
			if len(healthyInstances) > 0 {
				randomIndex := rand.IntN(len(healthyInstances))
				selectedInstance = healthyInstances[randomIndex]
				slog.Warn("LB (LeastConns): Fallback to random selection.", "instance_id", selectedInstance.InstanceID)
			} else {
				return nil, fmt.Errorf("critical LB error: no healthy instances available for least-connections fallback")
			}
		}


	case "random":
		fallthrough 
	default: 
		if len(healthyInstances) > 0 { 
			randomIndex := rand.IntN(len(healthyInstances))
			selectedInstance = healthyInstances[randomIndex]
			slog.Debug("LB (Random): Selected Tor instance.", "instance_id", selectedInstance.InstanceID)
		} else {
			return nil, fmt.Errorf("internal LB error: no healthy instances to select randomly from")
		}
	}

	if selectedInstance == nil { 
		slog.Error("LB: Critical error - No instance selected despite healthy options. Defaulting to the first healthy one if available.")
		if len(healthyInstances) > 0 {
			selectedInstance = healthyInstances[0]
		} else {
			return nil, fmt.Errorf("critical LB error: no healthy instances available at final selection")
		}
	}

	return selectedInstance, nil
}
