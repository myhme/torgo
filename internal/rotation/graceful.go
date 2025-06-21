package rotation

import (
	"context"
	"log"
	"time"
	"torgo/internal/config"
	"torgo/internal/tor"
)

// PerformGracefulRotation handles the full graceful rotation process for a single instance.
func PerformGracefulRotation(ctx context.Context, inst *tor.Instance, appCfg *config.AppConfig, reason string) {
	inst.StartDraining()
	log.Printf("%s: Instance %d is now draining. Waiting for active connections to close (timeout: %v).", reason, inst.InstanceID, appCfg.GracefulRotationTimeout)

	shutdownCtx, cancel := context.WithTimeout(ctx, appCfg.GracefulRotationTimeout)
	defer cancel()

	waitTicker := time.NewTicker(2 * time.Second)
	defer waitTicker.Stop()

	for inst.GetActiveConnections() > 0 {
		select {
		case <-shutdownCtx.Done():
			log.Printf("%s: Timed out waiting for connections on instance %d to close (%d remaining). Proceeding with rotation.", reason, inst.InstanceID, inst.GetActiveConnections())
			goto rotate
		case <-waitTicker.C:
		}
	}
	log.Printf("%s: All active connections on instance %d have closed.", reason, inst.InstanceID)

rotate:
	_, err := inst.SendTorCommand("SIGNAL NEWNYM")
	if err != nil {
		log.Printf("%s: Error rotating instance %d: %v", reason, inst.InstanceID, err)
	} else {
		log.Printf("%s: Successfully rotated instance %d.", reason, inst.InstanceID)
		inst.SetExternalIP("", time.Time{})
	}

	inst.StopDraining()
	log.Printf("%s: Instance %d is no longer draining and is back in the pool.", reason, inst.InstanceID)

	if appCfg.AutoRotateStaggerDelay > 0 {
		select {
		case <-time.After(appCfg.AutoRotateStaggerDelay):
		case <-ctx.Done():
			return
		}
	}
}