package secmem

import (
	"log"

	"golang.org/x/sys/unix"
)

// LockProcessMemoryBestEffort tries to lock all current and future pages into RAM
// to reduce swap/leak risk. Requires IPC_LOCK or a sufficient memlock ulimit.
func LockProcessMemoryBestEffort() error {
	return unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)
}

// DisableCoreDumpsAndPtrace tries to prevent coredumps and ptrace on this process.
// Best-effort: not a full defense against a root attacker.
func DisableCoreDumpsAndPtrace() {
	// Disallow core dumps
	var rlim unix.Rlimit
	rlim.Cur, rlim.Max = 0, 0
	if err := unix.Prlimit(0, unix.RLIMIT_CORE, &rlim, nil); err != nil {
		log.Printf("Hardening: failed to set RLIMIT_CORE: %v", err)
	}
	// Mark process non-dumpable (disallows ptrace from other UIDs)
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		log.Printf("Hardening: PR_SET_DUMPABLE failed: %v", err)
	}
}
