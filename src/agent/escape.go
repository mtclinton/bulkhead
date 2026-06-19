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

// vector class — the threat-model meaning of an escape attempt SUCCEEDING:
//
//	clsMediation     — a syscall-INVISIBLE I/O channel (io_uring) that would bypass the tier's mediation.
//	                   Must be denied in EVERY tier (gVisor ENOSYS, the FC guest kernel compiled it out,
//	                   the seccomp jail denies it by name).
//	clsHostReach     — reaching a resource that belongs to the HOST (unmediated network, the host control
//	                   socket, a host-only secret). A success here is a real escape in EVERY tier.
//	clsInSandboxPriv — gaining privilege WITHIN the sandbox (setuid/capset/ns/ptrace/module/raw-io/local-fs).
//	                   This = a HOST compromise only in the SHARED-KERNEL seccomp tier; in the gVisor and
//	                   Firecracker tiers the agent is in-sandbox/in-VM root BY DESIGN and the Sentry / VM
//	                   boundary contains it (ADR-0031's accepted residual: a Sentry/VMM 0-day, not in-guest uid).
type vclass int

const (
	clsMediation vclass = iota
	clsHostReach
	clsInSandboxPriv
)

func className(c vclass) string {
	switch c {
	case clsMediation:
		return "mediation"
	case clsHostReach:
		return "host-reach"
	default:
		return "in-sandbox-priv"
	}
}

// runEscapeProbe is the HOSTILE-payload live check (dispatched as `probe-escape`) — the agent ACTIVELY tries
// to break OUT of its jail across every vector a malicious agent would reach for, then reports the outcome so
// the harness can assert the floor held. It is TIER-AWARE (BULKHEAD_PROBE_TIER = seccomp|substrate, default
// seccomp): in the shared-kernel seccomp tier EVERY vector must be CONTAINED (in-sandbox privilege = host
// privilege); in the gVisor/Firecracker substrate tiers only the mediation + host-reach vectors must be
// contained, and an in-sandbox-privilege success is reported SANDBOX-PRIV (contained by the substrate, not a
// host escape). The rigorous rule: a "BREACH" is only a privileged op that actually SUCCEEDED in a class that
// is host-meaningful for this tier.
//
// Prints "ESCAPE <name>: CONTAINED|SANDBOX-PRIV|BREACH — [class] <detail>"; returns 0 iff NOTHING breached.
func runEscapeProbe() int {
	substrate := envOr("BULKHEAD_PROBE_TIER", "seccomp") == "substrate"
	breached := false
	npriv := 0
	report := func(name string, cls vclass, succeeded bool, detail string) {
		state := "CONTAINED"
		if succeeded {
			if cls == clsInSandboxPriv && substrate {
				state = "SANDBOX-PRIV" // privilege within the Sentry/VM — contained by the substrate boundary
				npriv++
			} else {
				state = "BREACH"
				breached = true
			}
		}
		fmt.Printf("ESCAPE %s: %s — [%s] %s\n", name, state, className(cls), detail)
	}

	// 1. IO_URING [mediation] — must be ENOSYS/EPERM in every tier; a ring (or even reachability) escapes the
	//    tier's seccomp/ptrace/Sentry mediation.
	var iour [120]byte
	if fd, _, errno := syscall.Syscall(sysIoUringSetup, 1, uintptr(unsafe.Pointer(&iour)), 0); errno == 0 {
		syscall.Close(int(fd))
		report("IO_URING", clsMediation, true, "io_uring_setup SUCCEEDED — a syscall-invisible I/O channel is reachable")
	} else if errno == syscall.EPERM || errno == syscall.ENOSYS {
		report("IO_URING", clsMediation, false, fmt.Sprintf("io_uring_setup denied (%v)", errno))
	} else {
		report("IO_URING", clsMediation, true, fmt.Sprintf("io_uring_setup reachable, errno %v", errno))
	}

	// 2. DIRECT_EGRESS [host-reach] — connect straight to a public host, bypassing the mediated proxy. An
	//    established connection is unmediated egress — a real escape in any tier.
	pub := envOr("BULKHEAD_PROBE_PUBLIC", "1.1.1.1:443")
	if c, err := net.DialTimeout("tcp", pub, 3*time.Second); err == nil {
		c.Close()
		report("DIRECT_EGRESS", clsHostReach, true, fmt.Sprintf("direct dial to %s SUCCEEDED — unmediated egress", pub))
	} else {
		report("DIRECT_EGRESS", clsHostReach, false, fmt.Sprintf("direct dial to %s failed (%v)", pub, err))
	}

	// 3. CONTROL_SOCK [host-reach] — reach the uid-0 control socket (the host TCB authority plane).
	if c, err := net.DialTimeout("unix", "/run/bulkhead/control.sock", 2*time.Second); err == nil {
		c.Close()
		report("CONTROL_SOCK", clsHostReach, true, "connected to /run/bulkhead/control.sock — reached the host TCB authority plane")
	} else {
		report("CONTROL_SOCK", clsHostReach, false, fmt.Sprintf("control.sock unreachable (%v)", err))
	}

	// 4. HOST_SECRET [host-reach] — the strongest tier-agnostic test: the HARNESS plants a secret file OUTSIDE
	//    the agent's sandbox view and passes its path; if the agent can read it, it crossed the fs boundary
	//    (a real escape in every tier). Only run when the harness provides it.
	if hs := os.Getenv("BULKHEAD_PROBE_HOST_SECRET"); hs != "" {
		if b, err := os.ReadFile(hs); err == nil && len(b) > 0 {
			report("HOST_SECRET", clsHostReach, true, fmt.Sprintf("read host-only secret %s — crossed the fs boundary", hs))
		} else {
			report("HOST_SECRET", clsHostReach, false, fmt.Sprintf("host-only secret %s unreadable (%v)", hs, err))
		}
	}

	// 5. SETUID [in-sandbox-priv] — become root. Host root in the seccomp tier; in-sandbox root (Sentry/VM) otherwise.
	if err := syscall.Setuid(0); err == nil && os.Geteuid() == 0 {
		report("SETUID", clsInSandboxPriv, true, "setuid(0) SUCCEEDED — gained root")
	} else {
		report("SETUID", clsInSandboxPriv, false, fmt.Sprintf("setuid(0) refused (euid still %d, %v)", os.Geteuid(), err))
	}

	// 6. CAPSET [in-sandbox-priv] — raise CAP_SYS_ADMIN.
	hdr := struct {
		version uint32
		pid     int32
	}{version: capVer3, pid: 0}
	var data [2]struct{ effective, permitted, inheritable uint32 }
	data[0].effective, data[0].permitted = 1<<capSysAdmin, 1<<capSysAdmin
	if _, _, errno := syscall.Syscall(sysCapset, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); errno == 0 {
		report("CAPSET", clsInSandboxPriv, true, "capset raised CAP_SYS_ADMIN — gained a capability")
	} else {
		report("CAPSET", clsInSandboxPriv, false, fmt.Sprintf("capset(CAP_SYS_ADMIN) refused (%v)", errno))
	}

	// 7. NEW_USERNS [in-sandbox-priv] — unshare a user+mount namespace.
	if _, _, errno := syscall.Syscall(sysUnshare, cloneNewuser|cloneNewns, 0, 0); errno == 0 {
		report("NEW_USERNS", clsInSandboxPriv, true, "unshare(CLONE_NEWUSER|CLONE_NEWNS) SUCCEEDED — got a fresh namespace")
	} else {
		report("NEW_USERNS", clsInSandboxPriv, false, fmt.Sprintf("unshare(user|mount ns) refused (%v)", errno))
	}

	// 8. PTRACE [in-sandbox-priv] — attach to PID 1.
	if _, _, errno := syscall.Syscall(sysPtrace, ptraceAttach, 1, 0); errno == 0 {
		report("PTRACE", clsInSandboxPriv, true, "ptrace(PTRACE_ATTACH, pid 1) SUCCEEDED — can trace another process")
	} else {
		report("PTRACE", clsInSandboxPriv, false, fmt.Sprintf("ptrace(ATTACH, pid 1) refused (%v)", errno))
	}

	// 9. MODULE [in-sandbox-priv] — load a kernel module. Host kernel in the seccomp tier; the guest/emulated
	//    kernel (substrate-contained) otherwise.
	if _, _, errno := syscall.Syscall(sysFinitModule, ^uintptr(0), uintptr(unsafe.Pointer(&[]byte{0}[0])), 0); errno == syscall.EPERM || errno == syscall.ENOSYS {
		report("MODULE", clsInSandboxPriv, false, fmt.Sprintf("finit_module refused (%v)", errno))
	} else {
		report("MODULE", clsInSandboxPriv, true, fmt.Sprintf("finit_module reachable (errno %v)", errno))
	}

	// 10. RAW_IO [in-sandbox-priv] — iopl(3): direct port I/O.
	if _, _, errno := syscall.Syscall(sysIopl, 3, 0, 0); errno == 0 {
		report("RAW_IO", clsInSandboxPriv, true, "iopl(3) SUCCEEDED — direct port I/O is reachable")
	} else {
		report("RAW_IO", clsInSandboxPriv, false, fmt.Sprintf("iopl(3) refused (%v)", errno))
	}

	// 11. FS_WRITE [in-sandbox-priv] — write under /usr (the local system tree). Host /usr in the seccomp tier
	//     (ProtectSystem=strict); the sandbox/guest /usr otherwise.
	esc := "/usr/.bulkhead-escape-probe"
	if err := os.WriteFile(esc, []byte("x"), 0o600); err == nil {
		os.Remove(esc)
		report("FS_WRITE", clsInSandboxPriv, true, "wrote to /usr — the local system tree is writable")
	} else {
		report("FS_WRITE", clsInSandboxPriv, false, fmt.Sprintf("write to /usr refused (%v)", err))
	}

	tierName := "seccomp"
	if substrate {
		tierName = "substrate"
	}
	if breached {
		fmt.Printf("ESCAPE RESULT: BREACH — a host-meaningful escape vector succeeded (tier=%s)\n", tierName)
		return 1
	}
	if substrate && npriv > 0 {
		fmt.Printf("ESCAPE RESULT: CONTAINED — no host-reach/mediation escape; %d in-sandbox-privilege op(s) succeeded but are contained by the %s boundary (ADR-0031 residual)\n", npriv, tierName)
	} else {
		fmt.Printf("ESCAPE RESULT: CONTAINED — every escape vector was denied (tier=%s)\n", tierName)
	}
	return 0
}
