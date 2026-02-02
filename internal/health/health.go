// internal/health/health.go — MONITOR ONLY (NO HEALING)
package health

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"torgo/internal/config"
)

// Per-instance state
type instanceState struct {
	healthy  uint32    // 1 = healthy, 0 = dead
	lastSeen time.Time
}

var states [32]*instanceState

func init() {
	for i := range states {
		states[i] = &instanceState{healthy: 1, lastSeen: time.Now()}
	}
}

// CheckSocks performs a strict SOCKS5 handshake.
// Shared by main.go and selfcheck.go.
func CheckSocks(port int) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	timeout := 1 * time.Second

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// 1. Send SOCKS5 Hello
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("write failed: %w", err)
	}

	// 2. Read Response
	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		return fmt.Errorf("read failed: %w", err)
	}

	if buf[0] != 0x05 || buf[1] != 0x00 {
		return fmt.Errorf("bad handshake: %x", buf)
	}

	return nil
}

func Monitor(ctx context.Context, insts []*config.Instance) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for idx, inst := range insts {
				checkInstance(inst, idx)
			}
		}
	}
}

func checkInstance(inst *config.Instance, idx int) {
	state := states[idx]

	// Try strict check
	if err := CheckSocks(inst.SocksPort); err == nil {
		if atomic.SwapUint32(&state.healthy, 1) == 0 {
			slog.Info("tor instance recovered (externally)", "id", inst.ID)
		}
		state.lastSeen = time.Now()
		return
	}

	// Mark as unhealthy, but DO NOT RESTART (No Guard Rotation)
	if atomic.SwapUint32(&state.healthy, 0) == 1 {
		slog.Error("tor instance unresponsive — manual intervention required", "id", inst.ID)
	}
}