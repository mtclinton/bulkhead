package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// x86_64 syscall numbers the stdlib doesn't always export (the appliance is qemux86-64 / core2-64).
const (
	sysPtrace      = 101
	sysUnshare     = 272
	sysCapset      = 126
	sysFinitModule = 313
	sysIopl        = 172
	ptraceAttach   = 16
	cloneNewuser   = 0x10000000 // CLONE_NEWUSER
	cloneNewns     = 0x00020000 // CLONE_NEWNS
	capVer3        = 0x20080522 // _LINUX_CAPABILITY_VERSION_3
	capSysAdmin    = 21         // CAP_SYS_ADMIN
)

// runEscapeProbe is the HOSTILE-payload live check (dispatched from main as `probe-escape`). Unlike the
// cooperative probe-egress (which confirms a few doors are locked), this is the agent ACTIVELY trying to
// break OUT of its jail across every vector a real malicious agent would reach for, then reporting the
// outcome so the harness can assert the floor held. It runs inside whichever tier launched it
// (confined no-route netns / runsc Sentry / Firecracker microVM); the denial MECHANISM differs per tier but
// every attempt must be CONTAINED. The rigorous rule: a "BREACH" is only ever a privileged operation that
// actually SUCCEEDED — a different failure errno still means the escape did not work (still contained).
//
// Prints one "ESCAPE <name>: CONTAINED|BREACH — <detail>" line per vector; returns 0 iff NOTHING breached.
func runEscapeProbe() int {
	breached := false
	report := func(name string, contained bool, detail string) {
		state := "CONTAINED"
		if !contained {
			state = "BREACH"
			breached = true
		}
		fmt.Printf("ESCAPE %s: %s — %s\n", name, state, detail)
	}

	// 1. IO_URING — a syscall-invisible I/O ring that escapes the tier's seccomp/ptrace mediation (ADR-0033).
	//    Must EPERM (seccomp by name) or ENOSYS (gVisor / the FC guest kernel compiled it out). Anything else
	//    means a ring is reachable.
	var iour [120]byte
	if fd, _, errno := syscall.Syscall(sysIoUringSetup, 1, uintptr(unsafe.Pointer(&iour)), 0); errno == 0 {
		syscall.Close(int(fd))
		report("IO_URING", false, "io_uring_setup SUCCEEDED — a syscall-invisible I/O channel is reachable")
	} else if errno == syscall.EPERM || errno == syscall.ENOSYS {
		report("IO_URING", true, fmt.Sprintf("io_uring_setup denied (%v)", errno))
	} else {
		report("IO_URING", false, fmt.Sprintf("io_uring_setup reachable, errno %v (ring not by-name denied)", errno))
	}

	// 2. SETUID — become root. DynamicUser + NoNewPrivileges must make setuid(0) EPERM and leave euid unchanged.
	if err := syscall.Setuid(0); err == nil && os.Geteuid() == 0 {
		report("SETUID", false, "setuid(0) SUCCEEDED — gained root")
	} else {
		report("SETUID", true, fmt.Sprintf("setuid(0) refused (euid still %d, %v)", os.Geteuid(), err))
	}

	// 3. CAPSET — raise a capability the jail emptied (CapabilityBoundingSet=, ADR-0005). Must EPERM.
	hdr := struct {
		version uint32
		pid     int32
	}{version: capVer3, pid: 0}
	var data [2]struct{ effective, permitted, inheritable uint32 }
	data[0].effective, data[0].permitted = 1<<capSysAdmin, 1<<capSysAdmin
	if _, _, errno := syscall.Syscall(sysCapset, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); errno == 0 {
		report("CAPSET", false, "capset raised CAP_SYS_ADMIN — gained a capability")
	} else {
		report("CAPSET", true, fmt.Sprintf("capset(CAP_SYS_ADMIN) refused (%v)", errno))
	}

	// 4. NEW_USERNS — unshare a user namespace (the classic path to caps inside the new ns). RestrictNamespaces
	//    must EPERM it; a success is a privilege-escalation foothold.
	if _, _, errno := syscall.Syscall(sysUnshare, cloneNewuser|cloneNewns, 0, 0); errno == 0 {
		report("NEW_USERNS", false, "unshare(CLONE_NEWUSER|CLONE_NEWNS) SUCCEEDED — got a fresh namespace")
	} else {
		report("NEW_USERNS", true, fmt.Sprintf("unshare(user|mount ns) refused (%v)", errno))
	}

	// 5. PTRACE — attach to PID 1 (read its memory / inject). E1 + yama + the jail must EPERM it.
	if _, _, errno := syscall.Syscall(sysPtrace, ptraceAttach, 1, 0); errno == 0 {
		report("PTRACE", false, "ptrace(PTRACE_ATTACH, pid 1) SUCCEEDED — can trace another process")
	} else {
		report("PTRACE", true, fmt.Sprintf("ptrace(ATTACH, pid 1) refused (%v)", errno))
	}

	// 6. MODULE — load a kernel module (the deepest escape: own the kernel). @module deny + the lockdown LSM
	//    must EPERM/ENOSYS. A bad-fd EBADF would mean the syscall is REACHABLE (neither seccomp nor lockdown
	//    blocked it) — a concern, so only EPERM/ENOSYS counts as contained.
	if _, _, errno := syscall.Syscall(sysFinitModule, ^uintptr(0), uintptr(unsafe.Pointer(&[]byte{0}[0])), 0); errno == syscall.EPERM || errno == syscall.ENOSYS {
		report("MODULE", true, fmt.Sprintf("finit_module refused (%v)", errno))
	} else {
		report("MODULE", false, fmt.Sprintf("finit_module reachable (errno %v — not blocked by @module/lockdown)", errno))
	}

	// 7. RAW_IO — iopl(3): direct port I/O, bypassing every kernel mediation. @raw-io deny + no CAP_SYS_RAWIO
	//    must EPERM.
	if _, _, errno := syscall.Syscall(sysIopl, 3, 0, 0); errno == 0 {
		report("RAW_IO", false, "iopl(3) SUCCEEDED — direct port I/O is reachable")
	} else {
		report("RAW_IO", true, fmt.Sprintf("iopl(3) refused (%v)", errno))
	}

	// 8. DIRECT_EGRESS — connect straight to a public host, bypassing the mediated proxy. The no-route netns /
	//    nftables drop / absent NIC must make it fail; an established connection is unmediated egress.
	pub := envOr("BULKHEAD_PROBE_PUBLIC", "1.1.1.1:443")
	if c, err := net.DialTimeout("tcp", pub, 3*time.Second); err == nil {
		c.Close()
		report("DIRECT_EGRESS", false, fmt.Sprintf("direct dial to %s SUCCEEDED — unmediated egress", pub))
	} else {
		report("DIRECT_EGRESS", true, fmt.Sprintf("direct dial to %s failed (%v)", pub, err))
	}

	// 9. FS_WRITE — write under /usr (ProtectSystem=strict). A successful write means the read-only system
	//    tree is mutable (tamper the binaries the next boot measures).
	esc := "/usr/.bulkhead-escape-probe"
	if err := os.WriteFile(esc, []byte("x"), 0o600); err == nil {
		os.Remove(esc)
		report("FS_WRITE", false, "wrote to /usr — the system tree is writable (ProtectSystem bypass)")
	} else {
		report("FS_WRITE", true, fmt.Sprintf("write to /usr refused (%v)", err))
	}

	// 10. CONTROL_SOCK — reach the uid-0 control socket (the TCB authority plane). A non-root DynamicUser agent
	//     must not even connect (0660 root, and it is outside the agent's mount namespace).
	if c, err := net.DialTimeout("unix", "/run/bulkhead/control.sock", 2*time.Second); err == nil {
		c.Close()
		report("CONTROL_SOCK", false, "connected to /run/bulkhead/control.sock — reached the TCB authority plane")
	} else {
		report("CONTROL_SOCK", true, fmt.Sprintf("control.sock unreachable (%v)", err))
	}

	if breached {
		fmt.Println("ESCAPE RESULT: BREACH — at least one escape vector succeeded")
		return 1
	}
	fmt.Println("ESCAPE RESULT: CONTAINED — every escape vector was denied")
	return 0
}
