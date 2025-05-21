package health

import (
	"context"
	"log/slog" // Import slog
	"time"

	"torgo/internal/config" 
	"torgo/internal/torinstance"
)

// Monitor periodically checks the health of all backend Tor instances.
func Monitor(ctx context.Context, instances []*torinstance.Instance, appCfg *config.AppConfig) {
	slog.Info("Health monitor started.")

	// Run initial check for all instances immediately
	for _, instance := range instances {
		go func(inst *torinstance.Instance) {
			// CheckHealth will use slog internally if it logs
			inst.CheckHealth(ctx) 
		}(instance)
	}

	ticker := time.NewTicker(appCfg.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			slog.Debug("Running periodic health checks for backend Tor instances...")
			for _, instance := range instances {
				go func(inst *torinstance.Instance) {
					inst.CheckHealth(ctx)
				}(instance)
			}
		case <-ctx.Done():
			slog.Info("Health monitor stopping due to context cancellation.")
			return
		}
	}
}
