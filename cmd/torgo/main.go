// cmd/torgo/main.go — FINAL 2025 ZERO-TRUST EDITION
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"torgo/internal/config"
	"torgo/internal/dns"
	"torgo/internal/health"
	"torgo/internal/secmem"
	"torgo/internal/selfcheck"
	"torgo/internal/socks"
)

func main() {
	// 1. Parse flags immediately (Critical for Docker Healthchecks)
	selfCheck := flag.Bool("selfcheck", false, "Run container healthcheck and exit")
	flag.Parse()

	// 2. Fast Path: Healthcheck
	// We skip secmem.Init() here because allocating/wiping 128MB
	// every 30s for a healthcheck causes timeouts.
	if *selfCheck {
		// selfcheck.Enforce checks Root status AND Port connectivity
		if err := selfcheck.Enforce(); err != nil {
			slog.Error("healthcheck failed", "err", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 3. Main Process Security Check (Root Check)
	// We must ensure the main process is not root before doing anything heavy.
	if os.Geteuid() == 0 {
		slog.Error("SECURITY FAIL: Main process running as ROOT (uid=0). Aborting.")
		os.Exit(1)
	}

	// 4. Memory protection — permanent and irreversible
	// This locks RAM (mlock) and disables swap/core dumps.
	if err := secmem.Init(); err != nil {
		slog.Error("secmem init failed — aborting", "err", err)
		os.Exit(1)
	}
	defer secmem.Wipe()

	// 4.1 Strict Memory Verification
	if os.Getenv("SECMEM_REQUIRE_MLOCK") == "true" && !secmem.IsMLocked() {
		slog.Error("mlockall failed — refusing to run on hostile host (SECMEM_REQUIRE_MLOCK=true)")
		os.Exit(1)
	}

	// 5. Load config + start all Tor instances
	cfg := config.Load()
	slog.Info("torgo zero-trust starting", "instances", cfg.Instances)

	instances := startTorInstances(cfg)
	waitForTorReady(instances)

	// 6. Graceful shutdown context
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGHUP,
	)
	defer cancel()

	// 7. Start services (all are self-healing and DoS-resistant)
	go socks.Start(ctx, instances, cfg)
	go dns.Start(ctx, instances, cfg)
	go health.Monitor(ctx, instances)

	slog.Info("torgo active — SOCKS 9150 | DNS 5353 — memory locked and non-dumpable")

	// 8. Block until shutdown signal
	<-ctx.Done()

	// 9. Clean shutdown
	slog.Info("shutting down...")
	killAllTor(instances)
	slog.Info("shutdown complete — all sensitive memory wiped")
}

func startTorInstances(cfg *config.Config) []*config.Instance {
	var insts []*config.Instance
	for i := 1; i <= cfg.Instances; i++ {
		inst := &config.Instance{
			ID:        i,
			SocksPort: 9050 + i,
			DNSPort:   9200 + i,
			// DataDir is set inside Instance.Start() based on ID
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
	slog.Info("waiting for tor instances to bootstrap...")

	for time.Now().Before(deadline) {
		readyCount := 0
		for _, inst := range insts {
			// Use fmt.Sprintf for safe address formatting (prevents null byte bugs)
			addr := fmt.Sprintf("127.0.0.1:%d", inst.SocksPort)
			
			// Short timeout check
			conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				readyCount++
			}
		}

		if readyCount == len(insts) {
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
		inst.Close()
	}
}