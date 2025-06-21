package lb

import (
	"fmt"
	"sync/atomic"

	"torgo/internal/tor"
)

var (
	counter uint64
)

func GetNextHealthyInstance(instances []*tor.Instance) (*tor.Instance, error) {
	if len(instances) == 0 {
		return nil, fmt.Errorf("loadbalancer: no instances provided")
	}

	eligibleInstances := make([]*tor.Instance, 0, len(instances))
	for _, instance := range instances {
		if instance.IsCurrentlyHealthy() && !instance.IsDraining() {
			eligibleInstances = append(eligibleInstances, instance)
		}
	}

	eligibleCount := len(eligibleInstances)
	if eligibleCount == 0 {
		return nil, fmt.Errorf("loadbalancer: no healthy and non-draining instances available")
	}

	nextIndex := atomic.AddUint64(&counter, 1) % uint64(eligibleCount)
	return eligibleInstances[nextIndex], nil
}