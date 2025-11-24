// internal/health/health.go — FINAL 2025 UNBREAKABLE VERSION
package health

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"torgo/internal/config"
)

// Per-instance state (atomic, lock-free)
type instanceState struct {
	healthy    uint32        // 1 = healthy, 0 = dead
	backoff    uint32        // seconds, capped at 300
	lastSeen   time.Time
	restartCnt uint64
}

var states [32]*instanceState // supports up to 32 instances

func init() {
	for i := range states {
		states[i] = &instanceState{healthy: 1}
	}
}

func Monitor(ctx context.Context, insts []*config.Instance) {
	ticker := time.NewTicker(15 * time.Second) // faster detection
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for idx, inst := range insts {
				checkAndHeal(ctx, inst, idx)
			}
		}
	}
}

func checkAndHeal(ctx context.Context, inst *config.Instance, idx int) {
	state := states[idx]

	// Fast path — already healthy and recent cookie
	if atomic.LoadUint32(&state.healthy) == 1 {
		if fi, err := os.Stat(inst.CookiePath()); err == nil && time.Since(fi.ModTime()) < 90*time.Second {
			state.lastSeen = time.Now()
			return
		}
	}

	// Something is wrong — mark unhealthy
	atomic.StoreUint32(&state.healthy, 0)
	backoff := atomic.LoadUint32(&state.backoff)
	if backoff == 0 {
		backoff = 1
	}

	if time.Since(state.lastSeen) < time.Duration(backoff)*time.Second {
		return // still in back-off
	}

	slog.Warn("tor instance dead → restarting", "id", inst.ID, "attempt", atomic.AddUint64(&state.restartCnt, 1))

	if err := inst.Restart(); err != nil {
		slog.Error("restart failed", "id", inst.ID, "err", err)
		// Exponential back-off, max 5 minutes
		newBackoff := backoff * 2
		if newBackoff > 300 {
			newBackoff = 300
		}
		atomic.StoreUint32(&state.backoff, newBackoff)
		return
	}

	// Success → reset everything
	atomic.StoreUint32(&state.healthy, 1)
	atomic.StoreUint32(&state.backoff, 0)
	state.lastSeen = time.Now()
	slog.Info("tor instance recovered", "id", inst.ID)
}