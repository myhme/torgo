package selfcheck

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"torgo/internal/config"
	"torgo/internal/health"
	"golang.org/x/net/proxy"
)

// Enforce performs the health check logic.
func Enforce() error {
	// 1. Security Check: Ensure not running as root
	if err := ensureNotRoot(); err != nil {
		return err
	}

	// 2. Connectivity Check: Ensure SOCKS proxy is responsive
	if err := checkSocksHandshake(); err != nil {
		return err
	}

	// 3. ZERO TRUST: Verify actual outbound traffic (Proof of Life)
	if err := verifyTorConnectivity(); err != nil {
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
	port, err := strconv.Atoi(cfg.SocksPort)
	if err != nil {
		return fmt.Errorf("invalid socks port: %v", err)
	}
	if err := health.CheckSocks(port); err != nil {
		return fmt.Errorf("LIVENESS FAIL: %w", err)
	}
	return nil
}

// verifyTorConnectivity attempts to fetch a tiny check URL through Tor
func verifyTorConnectivity() error {
	cfg := config.Load()
	
	// Setup SOCKS5 dialer
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:"+cfg.SocksPort, nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("failed to build dialer: %w", err)
	}

	// Create a transport that uses the SOCKS5 dialer
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// Attempt to reach the dedicated Tor Project check endpoint
	// This proves we have a built circuit and can exit.
	resp, err := client.Get("https://check.torproject.org/api/ip")
	if err != nil {
		return fmt.Errorf("TRAFFIC FAIL: Tor is not routing traffic: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("TRAFFIC FAIL: Bad status code from Tor check: %d", resp.StatusCode)
	}

	slog.Info("healthcheck: traffic verified (Tor circuit active)")
	return nil
}