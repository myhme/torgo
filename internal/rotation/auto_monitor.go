package rotation

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"torgo/internal/config"
	"torgo/internal/tor"
)

var autoRotationInProgress int32

func MonitorAutoRotation(ctx context.Context, instances []*tor.Instance, appCfg *config.AppConfig) {
	if !appCfg.IsAutoRotationEnabled || appCfg.AutoRotateCircuitInterval <= 0 {
		return
	}
	log.Printf("AutoRotationMonitor: Started. Circuit lifetime: %v, Stagger: %v.",
		appCfg.AutoRotateCircuitInterval, appCfg.AutoRotateStaggerDelay)

	checkInterval := appCfg.AutoRotateCircuitInterval / 10
	if checkInterval < 1*time.Minute { checkInterval = 1 * time.Minute }
	if checkInterval > 15*time.Minute { checkInterval = 15 * time.Minute }
    if appCfg.AutoRotateCircuitInterval < checkInterval && appCfg.AutoRotateCircuitInterval > 0 {
        checkInterval = appCfg.AutoRotateCircuitInterval / 2
        if checkInterval < 15*time.Second { checkInterval = 15*time.Second }
    }


	log.Printf("AutoRotationMonitor: Effective check interval: %v", checkInterval)
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			processEligibleInstanceForAutoRotation(ctx, instances, appCfg)
		case <-ctx.Done():
			log.Println("AutoRotationMonitor: Stopping.")
			atomic.StoreInt32(&autoRotationInProgress, 0)
			return
		}
	}
}

func processEligibleInstanceForAutoRotation(ctx context.Context, instances []*tor.Instance, appCfg *config.AppConfig) {
	if !atomic.CompareAndSwapInt32(&autoRotationInProgress, 0, 1) {
		return
	}
	var instanceToRotate *tor.Instance
	var oldestRecreationTime time.Time
	now := time.Now()

	for _, inst := range instances {
		if !inst.IsCurrentlyHealthy() {
			continue
		}
		lastRecTime, _ := inst.GetCircuitTimestamps()
		circuitAge := now.Sub(lastRecTime)
		if lastRecTime.IsZero() { // Treat never-rotated as infinitely old for first rotation
			circuitAge = appCfg.AutoRotateCircuitInterval + time.Second // Ensure it's eligible
		}

		if circuitAge >= appCfg.AutoRotateCircuitInterval {
			if instanceToRotate == nil || (!lastRecTime.IsZero() && lastRecTime.Before(oldestRecreationTime)) || (lastRecTime.IsZero() && !oldestRecreationTime.IsZero()) {
				instanceToRotate = inst
				oldestRecreationTime = lastRecTime
			} else if instanceToRotate == nil && lastRecTime.IsZero() {
                 instanceToRotate = inst
                 oldestRecreationTime = lastRecTime
            }
		}
	}

	if instanceToRotate != nil {
		log.Printf("AutoRotationMonitor: Rotating instance %d (LastRec: %v, Age: ~%v).",
			instanceToRotate.InstanceID, oldestRecreationTime, now.Sub(oldestRecreationTime))
		go func(selectedInstance *tor.Instance, cfg *config.AppConfig, parentCtx context.Context) {
			defer atomic.StoreInt32(&autoRotationInProgress, 0)
			_, err := selectedInstance.SendTorCommand("SIGNAL NEWNYM")
			if err != nil {
				log.Printf("AutoRotationMonitor: Error rotating instance %d: %v", selectedInstance.InstanceID, err)
			} else {
				log.Printf("AutoRotationMonitor: Rotated instance %d.", selectedInstance.InstanceID)
				selectedInstance.SetExternalIP("", time.Time{})
			}
			if cfg.AutoRotateStaggerDelay > 0 {
				select {
				case <-time.After(cfg.AutoRotateStaggerDelay):
				case <-parentCtx.Done():
					log.Printf("AutoRotationMonitor: Stagger for instance %d interrupted.", selectedInstance.InstanceID)
					return
				}
			}
		}(instanceToRotate, appCfg, ctx)
	} else {
		atomic.StoreInt32(&autoRotationInProgress, 0)
	}
}
