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

	// 2. Connectivity Check: Ensure SOCKS proxy is actually responsive
	// We perform a SOCKS5 handshake to ensure Tor is stable, not just listening.
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
	target := fmt.Sprintf("127.0.0.1:%s", cfg.SocksPort)
	timeout := 2 * time.Second

	// 1. Dial the TCP port
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return fmt.Errorf("LIVENESS FAIL: TCP dial failed to %s: %v", target, err)
	}
	defer conn.Close()

	// 2. Perform SOCKS5 Handshake (Lightweight)
	// We send the "Hello" to see if Tor accepts the protocol or drops us.
	// [VER=5, NMETHODS=1, METHOD=0(NoAuth)]
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("deadline error: %v", err)
	}

	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return fmt.Errorf("LIVENESS FAIL: SOCKS5 write failed: %v", err)
	}

	// 3. Read Response
	// We expect [VER=5, METHOD=0]
	// If Tor is initializing and resets the connection, this Read will fail.
	buf := make([]byte, 2)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("LIVENESS FAIL: SOCKS5 handshake read failed (Tor might be bootstrapping): %v", err)
	}
	if n != 2 || buf[0] != 0x05 || buf[1] != 0x00 {
		return fmt.Errorf("LIVENESS FAIL: Invalid SOCKS5 response: %x", buf[:n])
	}

	// If we got here, Tor is accepting SOCKS5 commands.
	slog.Info("healthcheck: passed (SOCKS5 handshake OK)", "uid", os.Geteuid(), "socks", target)
	return nil
}