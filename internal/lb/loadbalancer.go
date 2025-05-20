package lb

import (
	"fmt"
	"math/rand" // Required for random selection

	// "torgo/internal/config" // appCfg not directly needed by this function anymore for LBCurrentIndex
	"torgo/internal/torinstance"
)

// GetNextHealthyInstance selects a healthy backend Tor instance randomly from the pool.
func GetNextHealthyInstance(instances []*torinstance.Instance /* appCfg *config.AppConfig */) (*torinstance.Instance, error) {
	if len(instances) == 0 {
		return nil, fmt.Errorf("no backend Tor instances configured")
	}

	healthyInstances := make([]*torinstance.Instance, 0, len(instances))

	// Iterate through all instances and collect the healthy ones
	// Each instance's health status is protected by its own mutex.
	for _, instance := range instances {
		instance.Mu.Lock()
		isHealthy := instance.IsHealthy
		instance.Mu.Unlock()

		if isHealthy {
			healthyInstances = append(healthyInstances, instance)
		}
	}

	if len(healthyInstances) == 0 {
		// log.Println("LB: No healthy backend Tor instances available at this moment.") // This can be noisy
		return nil, fmt.Errorf("no healthy backend Tor instances available")
	}

	// Select a random instance from the pool of healthy ones
	randomIndex := rand.Intn(len(healthyInstances))
	selectedInstance := healthyInstances[randomIndex]

	// log.Printf("LB: Selected healthy Tor instance %d (%s) randomly from %d healthy options.",
	// 	selectedInstance.InstanceID, selectedInstance.BackendSocksHost, len(healthyInstances))

	return selectedInstance, nil
}
