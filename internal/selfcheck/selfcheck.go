package selfcheck

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"torgo/internal/config"
	"torgo/internal/health"
)

// Enforce performs the health check logic.
func Enforce() error {
	// 1. Security Check: Ensure not running as root
	if err := ensureNotRoot(); err != nil {
		return err
	}

	// 2. Connectivity Check: Ensure SOCKS proxy is actually responsive
	// We delegate the strict SOCKS5 handshake verification to the health package
	// to ensure consistency between startup checks and runtime monitoring.
	if err := checkSocksHandshake(); err != nil {
		return err
	}

	return nil
}

func ensureNotRoot() error {
	uid := os.Geteuid()
	if uid == 0 {
		return fmt.Errorf("SECURITY FAIL: Running as ROOT (uid=0)")
	}
	return nil
}

func checkSocksHandshake() error {
	cfg := config.Load()

	// Convert string port to int for the shared check
	port, err := strconv.Atoi(cfg.SocksPort)
	if err != nil {
		return fmt.Errorf("invalid socks port configuration: %v", err)
	}

	// Call the centralized strict check from internal/health
	if err := health.CheckSocks(port); err != nil {
		return fmt.Errorf("LIVENESS FAIL: %w", err)
	}

	// If we got here, Tor is accepting SOCKS5 commands.
	slog.Info("healthcheck: passed (SOCKS5 handshake OK)", "uid", os.Geteuid(), "socks_port", port)
	return nil
}