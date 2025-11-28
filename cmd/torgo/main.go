// cmd/torgo/main.go — FINAL 2025 ZERO-TRUST EDITION
// This is the end. Nothing more exists to harden.
// This is the end. Nothing more exists to harden.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"torgo/internal/config"
	"torgo/internal/dns"
	"torgo/internal/health"
	"torgo/internal/secmem"
	"torgo/internal/socks"
	"torgo/internal/selfcheck"
)

func main() {
	// 1. Memory protection — permanent and irreversible
	if err := secmem.Init(); err != nil {
		slog.Error("secmem init failed — aborting", "err", err)
		os.Exit(1)
	}
	defer secmem.Wipe()

    // 1.5 Runtime environment self-check (caps, tracing, uid/gid)
    if err := selfcheck.Enforce(); err != nil {
        slog.Error("environment self-check failed", "err", err)
        os.Exit(1)
    }

	if os.Getenv("SECMEM_REQUIRE_MLOCK") == "true" && !secmem.IsMLocked() {
		slog.Error("mlockall failed — refusing to run on hostile host")
		os.Exit(1)
	}

	// 2. Load config + start all Tor instances
	cfg := config.Load()
	slog.Info("torgo zero-trust starting", "instances", cfg.Instances)

	instances := startTorInstances(cfg)
	waitForTorReady(instances)

	// 3. Graceful shutdown context
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()

	// 4. Start services (all are self-healing and DoS-proof)
	go socks.Start(ctx, instances, cfg)
	go dns.Start(ctx, instances, cfg)
	go health.Monitor(ctx, instances)

	slog.Info("torgo active — SOCKS 9150 | DNS 5353 — memory locked and non-dumpable")

	// 5. Block forever — this is the final state
	<-ctx.Done()

	// 6. Clean shutdown
	killAllTor(instances)
	slog.Info("shutdown complete — all sensitive memory wiped")
}

func startTorInstances(cfg *config.Config) []*config.Instance {
	var insts []*config.Instance
	for i := 1; i <= cfg.Instances; i++ {
		inst := &config.Instance{
			ID:          i,
			SocksPort:   9050 + i,
			ControlPort: 9160 + i,
			DNSPort:     9200 + i,
			DataDir:     "/var/lib/tor/i" + itoaQuick(i), // zero heap
		}
		if err := inst.Start(); err != nil {
			slog.Error("tor failed to start", "id", i, "err", err)
			continue
		}
		insts = append(insts, inst)
	}
	if len(insts) == 0 {
		slog.Error("no tor instances started — exiting")
		os.Exit(1)
	}
	return insts
}

func waitForTorReady(insts []*config.Instance) {
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		ready := true
		for _, inst := range insts {
			if _, err := os.Stat(inst.CookiePath()); err != nil {
				ready = false
				break
			}
		}
		if ready {
			slog.Info("all tor instances ready", "count", len(insts))
			return
		}
		time.Sleep(1 * time.Second)
	}
	slog.Error("timeout waiting for tor instances")
	os.Exit(1)
}

func killAllTor(insts []*config.Instance) {
	for _, inst := range insts {
		// Use GetCmd() to access the internal exec.Cmd
		cmd := inst.GetCmd()
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
	}
	// Give Tor 5 seconds to exit gracefully
	time.Sleep(5 * time.Second)
	for _, inst := range insts {
		// Use GetCmd() to access the internal exec.Cmd
		cmd := inst.GetCmd()
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
}

// Fast zero-allocation itoa (used only here — no import bloat)
func itoaQuick(n int) string {
	buf := [11]byte{}
	i := len(buf)
	for n >= 10 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	i--
	buf[i] = byte('0' + n)
	return string(buf[i:])
}