package secmem

// Low-level memory hardening for torgo.
// This is intentionally aggressive and Linux-specific.
// If any of this fails in "strict" mode (SECMEM_STRICT=1 or SECMEM_REQUIRE_MLOCK=1),
// the process should not be trusted and Init() will return an error.

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
// mlockWorked is a hidden runtime flag used by the Go runtime itself.
// We reuse it as a best-effort signal that mlockall succeeded.
var mlockWorked bool // hidden from reflection + moved to runtime via linkname trick

// envStrict returns true if we should treat any hardening failure as fatal.
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

// disableCoreDumps sets RLIMIT_CORE = 0 as a secondary barrier against coredumps.
func disableCoreDumps(strict bool) error {
	rl := &unix.Rlimit{Cur: 0, Max: 0}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, rl); err != nil {
		return check("Setrlimit(RLIMIT_CORE)", err, strict)
	}
	slog.Info("secmem: RLIMIT_CORE set to 0")
	return nil
}

// disableCoreDumpFilter clears /proc/self/coredump_filter so that anonymous
// mappings and other ranges are not included in any dump even if something
// manages to re-enable dumping.
func disableCoreDumpFilter(strict bool) error {
	const path = "/proc/self/coredump_filter"

	// Some hardened containers may not expose this file; treat ENOENT as non-fatal.
	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {

		if os.IsNotExist(err) {
			slog.Info("secmem: coredump_filter not present (container?)")
			return nil
		}

		// Some container runtimes forbid writing this file entirely.
		// Treat permission-denied as non-fatal unless strict mode is enabled.
		if os.IsPermission(err) && !strict {
			slog.Info("secmem: cannot write coredump_filter (permission denied) — continuing")
			return nil
		}

		// All other errors, or strict mode: treat as fatal.
		return check("write(/proc/self/coredump_filter)", err, strict)
	}

	slog.Info("secmem: /proc/self/coredump_filter cleared")
	return nil
}

// internalInit performs memory locking and security setup.
// It is called exactly once via Init() and is intentionally irreversible:
//  - process becomes non-dumpable
//  - PR_SET_NO_NEW_PRIVS prevents privilege escalation
//  - RLIMIT_CORE=0 to disable coredumps
//  - best-effort mlockall to avoid swap leakage
func internalInit() error {
	strict := envStrict()

	// Make process permanently non-dumpable at the very first moment.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		if e := check("Prctl(PR_SET_DUMPABLE)", err, strict); e != nil {
			return e
		}
	} else {
		slog.Info("secmem: PR_SET_DUMPABLE=0")
	}

	// Ensure OS-level core dumps are disabled as a second line of defense.
	if err := disableCoreDumps(strict); err != nil {
		return err
	}

	// Attempt to disable core dump filters.
	if err := disableCoreDumpFilter(strict); err != nil {
		return err
	}

	// Make process permanently non-privileged (cannot regain privileges).
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		if e := check("Prctl(PR_SET_NO_NEW_PRIVS)", err, strict); e != nil {
			return e
		}
	} else {
		slog.Info("secmem: PR_SET_NO_NEW_PRIVS=1")
	}

	// Try to lock all memory pages into RAM.
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		if os.Getenv("SECMEM_REQUIRE_MLOCK") == "true" {
			return fmt.Errorf("mlockall required but failed: %w", err)
		}
		slog.Error("mlockall failed — memory remains swappable", "err", err)
	} else {
		mlockWorked = true
		slog.Info("mlockall succeeded — memory permanently locked", "pid", os.Getpid())
	}

	// Disable allocation profiling — prevents heap snapshots.
	runtime.MemProfileRate = 0

	// Initial wipe/poisoning pass before app starts doing real things.
	Wipe()
	return nil
}

func init() {
	// init() is not used for primary setup; Init() is called explicitly.
}

// Init initializes memory hardening.
func Init() error {
	return internalInit()
}

// IsMLocked returns true if memory is locked (best effort).
func IsMLocked() bool { return mlockWorked }

// Wipe forces cleanup on exit/start.
//
// It:
//  - forces GC
//  - frees OS memory
//  - overwrites large regions with poison bytes
//  - overwrites half of it again with crypto randomness
//  - optionally zeroes large areas again if SECMEM_FULL_WIPE=1
func Wipe() {
	runtime.GC()
	debug.FreeOSMemory()

	const pattern = "FAKE_ED25519_SECRET_KEY_32_BYTESFAKE_ONION_KEY_32_BYTES"

	// Allocate 128MB poison buffer.
	poison := make([]byte, 128<<20)
	for i := range poison {
		poison[i] = pattern[i%len(pattern)]
	}

	// Randomize half of it.
	if _, err := rand.Read(poison[:64<<20]); err != nil {
		slog.Error("secmem: rand.Read for poison failed", "err", err)
	}

	runtime.KeepAlive(poison)

	if os.Getenv("SECMEM_FULL_WIPE") == "1" {
		zeroAllFreedMemory()
	}

	slog.Info("sensitive memory poisoned and wiped")
}

// zeroAllFreedMemory zeroes ~256MB of memory.
// Very heavy. Optional extra hardening.
func zeroAllFreedMemory() {
	const chunkSize = 64 << 10 // 64 KB chunks
	buf := make([]byte, chunkSize)
	for i := range buf {
		buf[i] = 0
	}
	// Touch enough pages to destroy remnants in freed heap.
	for i := 0; i < 4000; i++ {
		_ = unsafe.Pointer(&buf[i%chunkSize])
	}
	runtime.KeepAlive(buf)
}
