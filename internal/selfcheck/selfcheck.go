package selfcheck

import (
	"fmt"
	"log/slog"
	"os"
)

func Enforce() error {
	if err := ensureNotRoot(); err != nil {
		return err
	}
	// Note: We don't check caps here because we dropped them in Docker.
	// If the runtime didn't drop them, we are still just user 100, so effective caps are 0.
	return nil
}

func ensureNotRoot() error {
	uid := os.Geteuid()
	if uid == 0 {
		return fmt.Errorf("SECURITY CRITICAL: Process is running as ROOT (uid=0). " +
			"This violates the zero-trust security model. " +
			"Check your Docker user settings.")
	}
	slog.Info("selfcheck: running as unprivileged user", "uid", uid)
	return nil
}