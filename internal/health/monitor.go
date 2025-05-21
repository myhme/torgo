package health

import (
	"context"
	"log"
	"time"

	"torgo/internal/config" // Assuming module path is 'torgo'
	"torgo/internal/torinstance"
)

// Monitor periodically checks the health of all backend Tor instances.
func Monitor(ctx context.Context, instances []*torinstance.Instance, appCfg *config.AppConfig) {
	log.Println("Health monitor started.")

	// Run initial check for all instances immediately
	// log.Println("Performing initial health checks for all backend Tor instances...")
	for _, instance := range instances {
		go func(inst *torinstance.Instance) {
			// Use a background context for initial checks if main app context isn't ready
			// or if these checks should not be cancelled by immediate shutdown signal.
			// However, using the passed 'ctx' is generally better for coordinated shutdown.
			inst.CheckHealth(ctx)
		}(instance)
	}

	ticker := time.NewTicker(appCfg.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// log.Println("Running periodic health checks for backend Tor instances...")
			for _, instance := range instances {
				go func(inst *torinstance.Instance) {
					// Create a new context for each check that can be cancelled
					// if the main application context is cancelled.
					// This checkCtx is not strictly necessary if inst.CheckHealth itself
					// takes a timeout or uses the main ctx.
					// inst.CheckHealth already has its own internal timeout.
					inst.CheckHealth(ctx) // Pass the main context
				}(instance)
			}
		case <-ctx.Done():
			log.Println("Health monitor stopping due to context cancellation.")
			return
		}
	}
}
