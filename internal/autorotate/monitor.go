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
		// instID := inst.InstanceID // This was the unused variable
		inst.Mu.Unlock()

		if !isHealthy {
			// log.Printf("AutoRotationMonitor: Instance %d is not healthy, skipping.", inst.InstanceID) // Use inst.InstanceID directly
			continue
		}

		// If LastCircuitRecreationTime is zero, it means it hasn't been rotated yet.
		// Consider it eligible if the instance has been up for at least the interval.
		// However, SendTorCommand updates this on first NEWNYM. If it's still zero,
		// it implies no NEWNYM has ever been successful.
		// For simplicity, if it's zero, we can treat it as very old.
		var circuitAge time.Duration
		if lastRecTime.IsZero() {
			// If never rotated, consider it "infinitely" old for rotation purposes,
			// or perhaps use its startup time if available (not tracked currently).
			// For now, if zero, it's a prime candidate if healthy.
			circuitAge = now.Sub(time.Time{}) // Effectively a very large duration
			// log.Printf("AutoRotationMonitor: Instance %d LastCircuitRecreationTime is zero.", inst.InstanceID) // Use inst.InstanceID
		} else {
			circuitAge = now.Sub(lastRecTime)
		}

		if circuitAge > appCfg.AutoRotateCircuitInterval {
			// log.Printf("AutoRotationMonitor: Instance %d is eligible for auto-rotation. Age: %v, LastRec: %v", inst.InstanceID, circuitAge, lastRecTime) // Use inst.InstanceID
			if instanceToRotate == nil || lastRecTime.Before(oldestRecreationTime) || (lastRecTime.IsZero() && !oldestRecreationTime.IsZero()) {
				instanceToRotate = inst
				oldestRecreationTime = lastRecTime // This will be zero if inst's lastRecTime is zero
				// log.Printf("AutoRotationMonitor: Instance %d is current candidate for rotation.", inst.InstanceID) // Use inst.InstanceID
			}
		}
	}

	if instanceToRotate != nil {
		log.Printf("AutoRotationMonitor: Selected instance %d for automatic circuit rotation (Last recreation: %v, Age: ~%v).",
			instanceToRotate.InstanceID, oldestRecreationTime, now.Sub(oldestRecreationTime))

		// Perform rotation in a new goroutine to not block the monitor's ticker,
		// and to handle the stagger delay before releasing the global lock.
		go func(selectedInstance *torinstance.Instance) {
			defer atomic.StoreInt32(&autoRotationInProgress, 0) // Release lock after this rotation attempt & stagger

			log.Printf("AutoRotationMonitor: Sending NEWNYM to instance %d.", selectedInstance.InstanceID)
			_, err := selectedInstance.SendTorCommand("SIGNAL NEWNYM") // SendTorCommand updates LastCircuitRecreationTime on success

			if err != nil {
				log.Printf("AutoRotationMonitor: Error auto-rotating instance %d: %v", selectedInstance.InstanceID, err)
			} else {
				log.Printf("AutoRotationMonitor: Successfully sent NEWNYM to instance %d for auto-rotation.", selectedInstance.InstanceID)
				// LastCircuitRecreationTime is updated within SendTorCommand
			}

			// Apply stagger delay before allowing another auto-rotation to be picked up
			if appCfg.AutoRotateStaggerDelay > 0 {
				// log.Printf("AutoRotationMonitor: Staggering for %v after rotating instance %d.", appCfg.AutoRotateStaggerDelay, selectedInstance.InstanceID)
				select {
				case <-time.After(appCfg.AutoRotateStaggerDelay):
				case <-ctx.Done(): // If main context is cancelled during stagger
					log.Printf("AutoRotationMonitor: Stagger delay for instance %d interrupted by shutdown.", selectedInstance.InstanceID)
					return
				}
			}
		}(instanceToRotate)
	} else {
		// No instance was eligible or selected, release the lock immediately.
		atomic.StoreInt32(&autoRotationInProgress, 0)
		// log.Println("AutoRotationMonitor: No instances currently eligible for auto-rotation.")
	}
}
