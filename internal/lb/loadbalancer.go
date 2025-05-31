package lb

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"torgo/internal/tor"
)

var (
	seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	randLock   sync.Mutex
)

func GetNextHealthyInstance(instances []*tor.Instance) (*tor.Instance, error) {
	if len(instances) == 0 { return nil, fmt.Errorf("loadbalancer: no instances") }
	healthyInstances := make([]*tor.Instance, 0, len(instances))
	for _, instance := range instances {
		if instance.IsCurrentlyHealthy() { healthyInstances = append(healthyInstances, instance) }
	}
	if len(healthyInstances) == 0 { return nil, fmt.Errorf("loadbalancer: no healthy instances") }
	randLock.Lock(); randomIndex := seededRand.Intn(len(healthyInstances)); randLock.Unlock()
	return healthyInstances[randomIndex], nil
}
