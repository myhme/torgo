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
	if !appCfg.IsAutoRotationEnabled || appCfg.AutoRotateCircuitInterval <= 0 { return }
	log.Printf("AutoRotationMonitor: Started. Lifetime: %v, Stagger: %v.", appCfg.AutoRotateCircuitInterval, appCfg.AutoRotateStaggerDelay)
	checkInterval := appCfg.AutoRotateCircuitInterval / 10
	if checkInterval < 1*time.Minute { checkInterval = 1 * time.Minute }
	if checkInterval > 15*time.Minute { checkInterval = 15 * time.Minute }
    if appCfg.AutoRotateCircuitInterval > 0 && appCfg.AutoRotateCircuitInterval < checkInterval {
        checkInterval = appCfg.AutoRotateCircuitInterval / 2
        if checkInterval < 15*time.Second { checkInterval = 15*time.Second }
    }
	log.Printf("AutoRotationMonitor: Effective check interval: %v", checkInterval)
	ticker := time.NewTicker(checkInterval); defer ticker.Stop()
	for {
		select {
		case <-ticker.C: processEligibleInstanceForAutoRotation(ctx, instances, appCfg)
		case <-ctx.Done(): log.Println("AutoRotationMonitor: Stopping."); atomic.StoreInt32(&autoRotationInProgress, 0); return
		}
	}
}
func processEligibleInstanceForAutoRotation(ctx context.Context, instances []*tor.Instance, appCfg *config.AppConfig) {
	if !atomic.CompareAndSwapInt32(&autoRotationInProgress, 0, 1) { return }
	var instanceToRotate *tor.Instance; var oldestRecTime time.Time; now := time.Now()
	for _, inst := range instances {
		if !inst.IsCurrentlyHealthy() { continue }
		lastRec, _ := inst.GetCircuitTimestamps(); age := now.Sub(lastRec)
		if lastRec.IsZero() { age = appCfg.AutoRotateCircuitInterval + time.Second }
		if age >= appCfg.AutoRotateCircuitInterval {
			if instanceToRotate == nil || (!lastRec.IsZero() && lastRec.Before(oldestRecTime)) || (lastRec.IsZero() && !oldestRecTime.IsZero()) {
				instanceToRotate = inst; oldestRecTime = lastRec
			} else if instanceToRotate == nil && lastRec.IsZero() { instanceToRotate = inst; oldestRecTime = lastRec }
		}
	}
	if instanceToRotate != nil {
		log.Printf("AutoRotation: Rotating inst %d (LastRec: %v, Age: ~%v).", instanceToRotate.InstanceID, oldestRecTime, now.Sub(oldestRecTime))
		go func(selInst *tor.Instance, cfg *config.AppConfig, pCtx context.Context) {
			defer atomic.StoreInt32(&autoRotationInProgress, 0)
			_, err := selInst.SendTorCommand("SIGNAL NEWNYM")
			if err != nil { log.Printf("AutoRotation: Err rotating inst %d: %v", selInst.InstanceID, err)
			} else { log.Printf("AutoRotation: Rotated inst %d.", selInst.InstanceID); selInst.SetExternalIP("", time.Time{}) }
			if cfg.AutoRotateStaggerDelay > 0 {
				select { case <-time.After(cfg.AutoRotateStaggerDelay): case <-pCtx.Done(): return }
			}
		}(instanceToRotate, appCfg, ctx)
	} else { atomic.StoreInt32(&autoRotationInProgress, 0) }
}
