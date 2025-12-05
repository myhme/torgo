package selfcheck

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// Enforce runs a series of environment checks and returns error
// if anything looks unsafe. Call this very early in main().
func Enforce() error {
	if err := ensureNotRoot(); err != nil {
		return err
	}
	if err := ensureNotTraced(); err != nil {
		return err
	}
	if err := ensureNoExtraCaps(); err != nil {
		return err
	}
	return nil
}

// ensureNotRoot forbids running as root unless explicitly allowed.
// Running as root is allowed only in two cases:
//   1. TORGO_ENABLE_LUKS_RAM=1 → LUKS setup requires root / SYS_ADMIN
//   2. TORGO_ALLOW_ROOT=1 → explicit override
func ensureNotRoot() error {
	uid := os.Geteuid()
	gid := os.Getegid()

	if uid == 0 || gid == 0 {
		luks := os.Getenv("TORGO_ENABLE_LUKS_RAM") == "1"
		allow := os.Getenv("TORGO_ALLOW_ROOT") == "1"

		if luks || allow {
			slog.Warn("selfcheck: running as root permitted by environment",
				"uid", uid, "gid", gid,
				"TORGO_ENABLE_LUKS_RAM", luks,
				"TORGO_ALLOW_ROOT", allow)
			return nil
		}

		return fmt.Errorf(
			"selfcheck: running as root (uid=%d gid=%d) is forbidden; "+
				"set TORGO_ALLOW_ROOT=1 or TORGO_ENABLE_LUKS_RAM=1 to allow",
			uid, gid)
	}

	slog.Info("selfcheck: uid/gid OK", "uid", uid, "gid", gid)
	return nil
}

// ensureNotTraced ensures TracerPid == 0.
func ensureNotTraced() error {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return fmt.Errorf("selfcheck: open /proc/self/status: %w", err)
	}
	defer f.Close()

	var tracerPid int64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				tracerPid, _ = strconv.ParseInt(fields[1], 10, 64)
			}
			break
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("selfcheck: read /proc/self/status: %w", err)
	}

	if tracerPid != 0 {
		return fmt.Errorf("selfcheck: process is being traced (TracerPid=%d)", tracerPid)
	}

	slog.Info("selfcheck: TracerPid=0")
	return nil
}

// ensureNoExtraCaps checks that effective capabilities are zero.
// This check is softened only if root is explicitly allowed for LUKS.
func ensureNoExtraCaps() error {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return fmt.Errorf("selfcheck: open /proc/self/status: %w", err)
	}
	defer f.Close()

	var capEff string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				capEff = fields[1]
			}
			break
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("selfcheck: read /proc/self/status: %w", err)
	}

	// If we are root *and* LUKS is enabled, capabilities are expected.
	if os.Geteuid() == 0 && os.Getenv("TORGO_ENABLE_LUKS_RAM") == "1" {
		slog.Info("selfcheck: CapEff may be nonzero due to LUKS setup",
			"CapEff", capEff)
		return nil
	}

	// Normal strict mode
	if capEff != "0000000000000000" && capEff != "0000000000000000\n" {
		return fmt.Errorf("selfcheck: unexpected effective capabilities (CapEff=%s)", capEff)
	}

	slog.Info("selfcheck: CapEff=0")
	return nil
}
