package selfcheck

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"torgo/internal/config"
)

// Enforce performs the health check logic.
func Enforce() error {
	// 1. Security Check: Ensure not running as root
	if err := ensureNotRoot(); err != nil {
		return err
	}

	// 2. Connectivity Check: Ensure SOCKS port is open
	if err := checkPorts(); err != nil {
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

func checkPorts() error {
	// Load config to find the correct port (reads env vars like COMMON_SOCKS_PROXY_PORT)
	cfg := config.Load()
	
	target := fmt.Sprintf("127.0.0.1:%s", cfg.SocksPort)
	
	// Try to connect to the SOCKS port with a short timeout
	conn, err := net.DialTimeout("tcp", target, 1*time.Second)
	if err != nil {
		return fmt.Errorf("LIVENESS FAIL: Cannot connect to SOCKS proxy at %s: %v", target, err)
	}
	conn.Close()
	
	slog.Info("healthcheck: passed", "uid", os.Geteuid(), "socks", target)
	return nil
}