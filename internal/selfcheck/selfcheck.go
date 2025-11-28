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

func ensureNotRoot() error {
	uid := os.Getuid()
	gid := os.Getgid()
	if uid == 0 || gid == 0 {
		return fmt.Errorf("selfcheck: running as root (uid=%d gid=%d) is forbidden", uid, gid)
	}
	slog.Info("selfcheck: uid/gid OK", "uid", uid, "gid", gid)
	return nil
}

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

// ensureNoExtraCaps checks that the effective capability set is zero.
// Inside a properly hardened container with cap_drop=ALL and no ambient
// caps, CapEff should be 0x0.
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

	if capEff != "0000000000000000" && capEff != "0000000000000000\n" {
		return fmt.Errorf("selfcheck: unexpected effective capabilities (CapEff=%s)", capEff)
	}
	slog.Info("selfcheck: CapEff=0")
	return nil
}
