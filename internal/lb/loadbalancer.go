package lb

import (
	"fmt"
	"log"
	"math/rand"
	"sync/atomic" // For RoundRobinIndex

	"torgo/internal/config"
	"torgo/internal/torinstance"
)

var roundRobinIndex uint32 // Used for "round-robin" strategy

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
		// log.Printf("LB (RoundRobin): Selected Tor instance %d. Current index: %d", selectedInstance.InstanceID, currentIndex)

	case "least-connections-proxy":
		var minConns int32 = -1 // Use -1 to indicate first healthy instance
		for _, inst := range healthyInstances {
			currentConns := inst.GetActiveProxyConnections()
			if selectedInstance == nil || currentConns < minConns {
				minConns = currentConns
				selectedInstance = inst
			}
		}
		// log.Printf("LB (LeastConns): Selected Tor instance %d with %d active proxy conns.", selectedInstance.InstanceID, minConns)

	case "random":
		fallthrough // Fallthrough to random if strategy is "random"
	default: // Default to random if strategy is unknown or "random"
		randomIndex := rand.Intn(len(healthyInstances))
		selectedInstance = healthyInstances[randomIndex]
		// log.Printf("LB (Random): Selected Tor instance %d.", selectedInstance.InstanceID)
	}

	if selectedInstance == nil { // Should not happen if healthyInstances is not empty
		log.Println("LB: Critical error - No instance selected despite healthy options. Defaulting to random.")
		randomIndex := rand.Intn(len(healthyInstances))
		selectedInstance = healthyInstances[randomIndex]
	}

	return selectedInstance, nil
}
