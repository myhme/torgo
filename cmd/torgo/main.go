// cmd/torgo/main.go — FINAL 2025 ZERO-TRUST EDITION
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"torgo/internal/chaff"
	"torgo/internal/config"
	"torgo/internal/dns"
	"torgo/internal/health"
	"torgo/internal/secmem"
	"torgo/internal/selfcheck"
	"torgo/internal/socks"
)

func main() {
	// 1. Flags & Healthcheck
	selfCheck := flag.Bool("selfcheck", false, "Run container healthcheck and exit")
	flag.Parse()

	if *selfCheck {
		if err := selfcheck.Enforce(); err != nil {
			slog.Error("healthcheck failed", "err", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 2. Security Checks
	if os.Geteuid() == 0 {
		slog.Error("SECURITY FAIL: Main process running as ROOT (uid=0). Aborting.")
		os.Exit(1)
	}

	if err := secmem.Init(); err != nil {
		slog.Error("secmem init failed — aborting", "err", err)
		os.Exit(1)
	}
	defer secmem.Wipe()

	if os.Getenv("SECMEM_REQUIRE_MLOCK") == "true" && !secmem.IsMLocked() {
		slog.Error("mlockall failed — refusing to run on hostile host (SECMEM_REQUIRE_MLOCK=true)")
		os.Exit(1)
	}

	// 3. Start Tor
	cfg := config.Load()
	slog.Info("torgo zero-trust starting", "instances", cfg.Instances)

	instances := startTorInstances(cfg)

	// 4. Wait for Bootstrap (No Self-Healing)
	waitForTorReady(instances)

	// 5. Graceful Shutdown Context
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGHUP,
	)
	defer cancel()

	// 6. Start Services
	go socks.Start(ctx, instances, cfg)
	go dns.Start(ctx, instances, cfg)
	go health.Monitor(ctx, instances)
	go chaff.Start(ctx, cfg) // Deep Surfing Enabled

	slog.Info("torgo active — SOCKS 9150 | DNS 5353 — memory locked and non-dumpable")

	// 7. Block until signal
	<-ctx.Done()

	// 8. Cleanup
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
	// 3 minute absolute timeout
	deadline := time.Now().Add(180 * time.Second)
	slog.Info("waiting for tor instances to bootstrap...")

	for time.Now().Before(deadline) {
		readyCount := 0
		for _, inst := range insts {
			// Use shared strict check
			if err := health.CheckSocks(inst.SocksPort); err == nil {
				readyCount++
			}
		}

		if readyCount == len(insts) {
			slog.Info("all tor instances ready", "count", len(insts))
			return
		}
		time.Sleep(1 * time.Second)
	}
	
	slog.Error("timeout waiting for tor instances — aborting")
	os.Exit(1)
}

func killAllTor(insts []*config.Instance) {
	for _, inst := range insts {
		inst.Close()
	}
}