package lb

import (
	"fmt"
	// "log" // Uncomment if verbose logging is needed
	// "sync/atomic" // Uncomment if using atomic for LBCurrentIndex

	"torgo/internal/config" // Assuming module path is 'torgo'
	"torgo/internal/torinstance"
)

// GetNextHealthyInstance selects a healthy backend Tor instance using round-robin.
func GetNextHealthyInstance(instances []*torinstance.Instance, appCfg *config.AppConfig) (*torinstance.Instance, error) {
	appCfg.LBMutex.Lock() // Protects LBCurrentIndex and access to instances slice for consistent view
	defer appCfg.LBMutex.Unlock()

	if len(instances) == 0 {
		return nil, fmt.Errorf("no backend Tor instances configured")
	}
	
	numInstances := int32(len(instances))
	if numInstances == 0 { // Should be caught by len(instances) == 0, but defensive
		return nil, fmt.Errorf("no backend Tor instances available (numInstances is 0)")
	}


	// Start search from (currentIndex + 1) to ensure round-robin
	// LBCurrentIndex is 0-based.
	// We iterate up to numInstances times to check every instance once in a round-robin fashion.
	for i := int32(0); i < numInstances; i++ {
		// Calculate next index in round-robin manner
		// appCfg.LBCurrentIndex is the last *successfully selected* index, or -1 initially.
		// We want to try the *next* one.
		currentIndexToTry := (appCfg.LBCurrentIndex + 1 + i) % numInstances
		instance := instances[currentIndexToTry]

		instance.Mu.Lock() // Lock instance to read its health status
		healthy := instance.IsHealthy
		instance.Mu.Unlock()

		if healthy {
			// log.Printf("LB: Selected healthy Tor instance %d (%s)", instance.InstanceID, instance.BackendSocksHost)
			appCfg.LBCurrentIndex = currentIndexToTry // Update the global index to the selected one
			return instance, nil
		}
		// log.Printf("LB: Skipped unhealthy Tor instance %d", instance.InstanceID)
	}
	// log.Println("LB: No healthy backend Tor instances available after checking all.")
	return nil, fmt.Errorf("no healthy backend Tor instances available")
}
