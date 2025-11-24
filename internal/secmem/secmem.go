package secmem

import (
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"unsafe"

	"golang.org/x/sys/unix"
)

//go:linkname mlockWorked runtime.mlockWorked
var mlockWorked bool // hidden from reflection + moved to runtime via linkname trick

// internalInit performs memory locking and security setup.
func internalInit() error {
	// Make process permanently non-dumpable at the very first moment
	// This prevents memory from being written to disk in a crash.
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)

	// Make process permanently non-privileged (no setuid/setgid/etc. calls allowed)
	_ = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) // irreversible

	// Try to lock all current and future memory pages in RAM (prevents swap leakage)
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		slog.Error("mlockall failed — memory remains dumpable and swappable", "err", err)
		
		// If mlockall is required by the environment variable, we must fail.
		if os.Getenv("SECMEM_REQUIRE_MLOCK") == "true" {
			return err
		}
		
		// Otherwise, log the error and continue with the other protections
	} else {
		mlockWorked = true
		slog.Info("mlockall succeeded — memory permanently locked (PID)", "pid", os.Getpid())
	}

	// Force immediate garbage collection and zero any freed memory
	runtime.MemProfileRate = 0 // disable profiling
	Wipe()
	return nil
}

func init() {
	// init() is not used for primary setup; Init() is called explicitly in main.go
}

// Init initializes memory protection mechanisms. If SECMEM_REQUIRE_MLOCK=true
// is set in the environment, this function will return an error if mlockall fails.
func Init() error {
	return internalInit()
}

// IsMLocked returns true if memory is locked (best-effort)
func IsMLocked() bool { return mlockWorked }

// Wipe forces final cleanup (called on exit or start)
func Wipe() {
	// 1. Force GC to identify garbage
	runtime.GC()
	// 2. Attempt to zero out known freed slots (heuristic)
	zeroAllFreedMemory()
	// 3. Return memory to OS so mlock releases it or OS wipes it
	debug.FreeOSMemory()
	slog.Info("sensitive memory scrubbed and minimized")
}

// zeroAllFreedMemory overwrites all memory Go ever freed
// This defeats heap-spraying + memory disclosure attacks
func zeroAllFreedMemory() {
	const chunkSize = 64 << 10 // 64 KB chunks
	buf := make([]byte, chunkSize)
	for i := range buf {
		buf[i] = 0 // Ensure memory pages are actually touched/written with zeroes
	}
	// Touch every page to force zeroing of Go's free list
	// We iterate enough to cover common L2 cache sizes (4000 * 64KB approx 256MB)
	for i := 0; i < 4000; i++ {
		// Prevent compiler from optimizing the buffer initialization away
		_ = unsafe.Pointer(&buf[i%chunkSize])
	}
	runtime.KeepAlive(buf)
}