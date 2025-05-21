package autorotate

import (
	"context"
	"log"
	"sync/atomic"
	"time"
	"torgo/internal/config"
	"torgo/internal/torinstance"
)

var (
	// autoRotationInProgress is a flag to ensure only one auto-rotation happens globally
	// across all instances during a stagger delay period.
	// 0 = not in progress, 1 = in progress.
	autoRotationInProgress int32
)

// MonitorAutoRotation periodically checks if instances need their circuits rotated
// based on the AutoRotateCircuitInterval and staggers the rotations.
func MonitorAutoRotation(ctx context.Context, instances []*torinstance.Instance, appCfg *config.AppConfig) {
	if !appCfg.IsAutoRotationEnabled || appCfg.AutoRotateCircuitInterval <= 0 {
		log.Println("AutoRotationMonitor: Disabled by configuration.")
		return
	}

	log.Printf("AutoRotationMonitor: Started. Circuit lifetime: %v, Stagger delay: %v. Checking instances periodically.",
		appCfg.AutoRotateCircuitInterval, appCfg.AutoRotateStaggerDelay)

	// The ticker interval for checking can be different from the rotation interval itself.
	// Shorter check interval means more responsive to picking up stale circuits.
	// For example, check every 1-5 minutes.
	checkInterval := 1 * time.Minute
	if appCfg.AutoRotateCircuitInterval < 5*time.Minute { // If rotation interval is very short, check more frequently
		checkInterval = appCfg.AutoRotateCircuitInterval / 5
		if checkInterval < 30*time.Second {
			checkInterval = 30 * time.Second // Minimum check interval
		}
	}
	log.Printf("AutoRotationMonitor: Check interval set to %v", checkInterval)
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// log.Println("AutoRotationMonitor: Tick. Checking for stale circuits...")
			processEligibleInstanceForAutoRotation(ctx, instances, appCfg)
		case <-ctx.Done():
			log.Println("AutoRotationMonitor: Stopping due to context cancellation.")
			return
		}
	}
}

func processEligibleInstanceForAutoRotation(ctx context.Context, instances []*torinstance.Instance, appCfg *config.AppConfig) {
	if !atomic.CompareAndSwapInt32(&autoRotationInProgress, 0, 1) {
		// log.Println("AutoRotationMonitor: An auto-rotation is already in progress or recently completed (respecting stagger). Skipping this check cycle for new rotations.")
		return // Another rotation is being processed, respect stagger delay by not starting a new one immediately.
	}
	// If we successfully swapped, we 'own' the lock now. Release it after potential rotation + stagger.

	var instanceToRotate *torinstance.Instance
	var oldestRecreationTime time.Time

	now := time.Now()

	for _, inst := range instances {
		inst.Mu.Lock()
		isHealthy := inst.IsHealthy
		lastRecTime := inst.LastCircuitRecreationTime
		inst.Mu.Unlock()

		if !isHealthy {
			// log.Printf("AutoRotationMonitor: Instance %d is not healthy, skipping.", inst.InstanceID)
			continue
		}

		var circuitAge time.Duration
		if lastRecTime.IsZero() {
			circuitAge = now.Sub(time.Time{}) 
			// log.Printf("AutoRotationMonitor: Instance %d LastCircuitRecreationTime is zero.", inst.InstanceID)
		} else {
			circuitAge = now.Sub(lastRecTime)
		}

		if circuitAge > appCfg.AutoRotateCircuitInterval {
			// log.Printf("AutoRotationMonitor: Instance %d is eligible for auto-rotation. Age: %v, LastRec: %v", inst.InstanceID, circuitAge, lastRecTime)
			if instanceToRotate == nil || lastRecTime.Before(oldestRecreationTime) || (lastRecTime.IsZero() && !oldestRecreationTime.IsZero()) {
				instanceToRotate = inst
				oldestRecreationTime = lastRecTime 
				// log.Printf("AutoRotationMonitor: Instance %d is current candidate for rotation.", inst.InstanceID)
			}
		}
	}

	if instanceToRotate != nil {
		log.Printf("AutoRotationMonitor: Selected instance %d for automatic circuit rotation (Last recreation: %v, Age: ~%v).",
			instanceToRotate.InstanceID, oldestRecreationTime, now.Sub(oldestRecreationTime))

		go func(selectedInstance *torinstance.Instance) {
			defer atomic.StoreInt32(&autoRotationInProgress, 0) 

			log.Printf("AutoRotationMonitor: Sending NEWNYM to instance %d.", selectedInstance.InstanceID)
			_, err := selectedInstance.SendTorCommand("SIGNAL NEWNYM") 

			if err != nil {
				log.Printf("AutoRotationMonitor: Error auto-rotating instance %d: %v", selectedInstance.InstanceID, err)
			} else {
				log.Printf("AutoRotationMonitor: Successfully sent NEWNYM to instance %d for auto-rotation.", selectedInstance.InstanceID)
			}

			if appCfg.AutoRotateStaggerDelay > 0 {
				// log.Printf("AutoRotationMonitor: Staggering for %v after rotating instance %d.", appCfg.AutoRotateStaggerDelay, selectedInstance.InstanceID)
				select {
				case <-time.After(appCfg.AutoRotateStaggerDelay): // This is line 108 in this version
				case <-ctx.Done(): 
					log.Printf("AutoRotationMonitor: Stagger delay for instance %d interrupted by shutdown.", selectedInstance.InstanceID)
					return
				}
			}
		}(instanceToRotate)
	} else {
		atomic.StoreInt32(&autoRotationInProgress, 0)
		// log.Println("AutoRotationMonitor: No instances currently eligible for auto-rotation.")
	}
}
