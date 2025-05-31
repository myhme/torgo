package health

import (
	"context"
	"log"
	"time"

	"torgo/internal/config"
	"torgo/internal/tor"
)

func Monitor(ctx context.Context, instances []*tor.Instance, appCfg *config.AppConfig) {
	if appCfg.HealthCheckInterval <= 0 { log.Println("Health monitor disabled (interval <= 0)."); return }
	log.Printf("Health monitor started. Interval: %v", appCfg.HealthCheckInterval)
	ticker := time.NewTicker(appCfg.HealthCheckInterval); defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			for _, instance := range instances { go func(inst *tor.Instance) { inst.CheckHealth(ctx) }(instance) }
		case <-ctx.Done(): log.Println("Health monitor stopping."); return
		}
	}
}
