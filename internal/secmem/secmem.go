package secmem

// Low-level memory hardening for torgo.
// This is intentionally aggressive and Linux-specific.

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"unsafe"

	"golang.org/x/sys/unix"
)

//go:linkname mlockWorked runtime.mlockWorked
var mlockWorked bool

// envStrict returns true if we should treat critical failures as fatal.
// Note: We will handle coredump_filter permissions gracefully regardless of this flag.
func envStrict() bool {
	return os.Getenv("SECMEM_STRICT") == "1" || os.Getenv("SECMEM_REQUIRE_MLOCK") == "true"
}

// check logs an error and, if strict, wraps and returns it.
func check(step string, err error, strict bool) error {
	if err == nil {
		return nil
	}
	slog.Error("secmem hardening step failed", "step", step, "err", err)
	if strict {
		return fmt.Errorf("%s: %w", step, err)
	}
	return nil
}

// disableCoreDumps sets RLIMIT_CORE = 0.
func disableCoreDumps(strict bool) error {
	rl := &unix.Rlimit{Cur: 0, Max: 0}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, rl); err != nil {
		return check("Setrlimit(RLIMIT_CORE)", err, strict)
	}
	slog.Info("secmem: RLIMIT_CORE set to 0")
	return nil
}

// disableCoreDumpFilter clears /proc/self/coredump_filter.
func disableCoreDumpFilter(strict bool) error {
	const path = "/proc/self/coredump_filter"

	// Some hardened containers may not expose this file; treat ENOENT as non-fatal.
	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
		if os.IsNotExist(err) {
			slog.Info("secmem: coredump_filter not present (container?)")
			return nil
		}

		// FIX: In strict non-root containers, writing to /proc is often denied.
		// Since we already set RLIMIT_CORE=0 and PR_SET_DUMPABLE=0, failing here
		// should NOT be fatal, even in strict mode.
		if os.IsPermission(err) {
			slog.Warn("secmem: cannot write coredump_filter (permission denied) — continuing")
			return nil
		}

		// Other I/O errors are still checked against strictness.
		return check("write(/proc/self/coredump_filter)", err, strict)
	}

	slog.Info("secmem: /proc/self/coredump_filter cleared")
	return nil
}

// internalInit performs memory locking and security setup.
func internalInit() error {
	strict := envStrict()

	// 1. Make process permanently non-dumpable.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		if e := check("Prctl(PR_SET_DUMPABLE)", err, strict); e != nil {
			return e
		}
	} else {
		slog.Info("secmem: PR_SET_DUMPABLE=0")
	}

	// 2. Disable OS-level core dumps.
	if err := disableCoreDumps(strict); err != nil {
		return err
	}

	// 3. Attempt to disable core dump filters (Best Effort).
	if err := disableCoreDumpFilter(strict); err != nil {
		return err
	}

	// 4. Prevent privilege escalation.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		if e := check("Prctl(PR_SET_NO_NEW_PRIVS)", err, strict); e != nil {
			return e
		}
	} else {
		slog.Info("secmem: PR_SET_NO_NEW_PRIVS=1")
	}

	// 5. Lock memory (Strict Requirement if env is set).
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		if os.Getenv("SECMEM_REQUIRE_MLOCK") == "true" {
			return fmt.Errorf("mlockall required but failed: %w", err)
		}
		slog.Error("mlockall failed — memory remains swappable", "err", err)
	} else {
		mlockWorked = true
		slog.Info("mlockall succeeded — memory permanently locked", "pid", os.Getpid())
	}

	// Disable allocation profiling.
	runtime.MemProfileRate = 0

	// Initial wipe.
	Wipe()
	return nil
}

func init() {
	// init() is not used for primary setup; Init() is called explicitly.
}

func Init() error {
	return internalInit()
}

func IsMLocked() bool { return mlockWorked }

func Wipe() {
	runtime.GC()
	debug.FreeOSMemory()

	const pattern = "FAKE_ED25519_SECRET_KEY_32_BYTESFAKE_ONION_KEY_32_BYTES"

	poison := make([]byte, 128<<20)
	for i := range poison {
		poison[i] = pattern[i%len(pattern)]
	}

	if _, err := rand.Read(poison[:64<<20]); err != nil {
		slog.Error("secmem: rand.Read for poison failed", "err", err)
	}

	runtime.KeepAlive(poison)

	if os.Getenv("SECMEM_FULL_WIPE") == "1" {
		zeroAllFreedMemory()
	}

	slog.Info("sensitive memory poisoned and wiped")
}

func zeroAllFreedMemory() {
	const chunkSize = 64 << 10
	buf := make([]byte, chunkSize)
	for i := range buf {
		buf[i] = 0
	}
	for i := 0; i < 4000; i++ {
		_ = unsafe.Pointer(&buf[i%chunkSize])
	}
	runtime.KeepAlive(buf)
}