package lb

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"torgo/internal/tor"
)

var (
	// For true round-robin, if ever implemented
	// currentIndex int
	// rrMutex      sync.Mutex

	// Seed random number generator once
	seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	randLock   sync.Mutex
)

// GetNextHealthyInstance selects a healthy backend Tor instance randomly.
func GetNextHealthyInstance(instances []*tor.Instance) (*tor.Instance, error) {
	if len(instances) == 0 {
		return nil, fmt.Errorf("loadbalancer: no backend Tor instances configured")
	}

	healthyInstances := make([]*tor.Instance, 0, len(instances))
	for _, instance := range instances {
		if instance.IsCurrentlyHealthy() {
			healthyInstances = append(healthyInstances, instance)
		}
	}

	if len(healthyInstances) == 0 {
		return nil, fmt.Errorf("loadbalancer: no healthy backend Tor instances available")
	}

	randLock.Lock()
	randomIndex := seededRand.Intn(len(healthyInstances))
	randLock.Unlock()
	selectedInstance := healthyInstances[randomIndex]

	return selectedInstance, nil
}
