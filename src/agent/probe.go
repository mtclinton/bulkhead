package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

// sysIoUringSetup is the io_uring_setup(2) syscall number on x86_64 (the appliance is
// qemux86-64 / core2-64; the stdlib syscall package doesn't export SYS_IO_URING_SETUP).
const sysIoUringSetup = 425

// runEgressProbe is the ADR-0034 increment-1 live check (dispatched from main). It runs
// inside the jailed agent's no-route netns and verifies, in order:
//
//  1. NOROUTE    — a direct dial to a public IP fails (the netns has no default route);
//  2. ISOLATED   — a direct dial to the host-loopback test service fails (the agent's own
//     loopback is separate from the host's, so the service is unreachable);
//  3. PROXY-OK   — the SAME host-loopback service IS reachable through the egress-proxy UDS
//     (the single mediated path works and bridges the namespace boundary);
//  4. PROXY-DENY — a non-allowlisted destination through the proxy is refused.
//  5. IOURING    — io_uring_setup is seccomp-denied (ADR-0033): an io_uring ring would be a
//     syscall-invisible I/O channel that escapes the jail's mediation, so it must EPERM.
//
// It prints one "PROBE <name>: PASS|FAIL" line per check and returns 0 iff all pass.
func runEgressProbe() int {
	pub := envOr("BULKHEAD_PROBE_PUBLIC", "1.1.1.1:443")
	target := envOr("BULKHEAD_PROBE_TARGET", "127.0.0.1:8088")
	denied := envOr("BULKHEAD_PROBE_DENIED", "10.255.255.1:80")
	sock := os.Getenv("BULKHEAD_EGRESS_SOCK")

	ok := true
	report := func(name string, pass bool, detail string) {
		ok = ok && pass
		state := "FAIL"
		if pass {
			state = "PASS"
		}
		fmt.Printf("PROBE %s: %s — %s\n", name, state, detail)
	}

	// 1. NOROUTE — a direct connect to a public address must fail (no route in the netns).
	if c, err := net.DialTimeout("tcp", pub, 3*time.Second); err == nil {
		c.Close()
		report("NOROUTE", false, fmt.Sprintf("direct dial to %s SUCCEEDED (the netns has a route!)", pub))
	} else {
		report("NOROUTE", true, fmt.Sprintf("direct dial to %s failed as expected (%v)", pub, err))
	}

	// 2. ISOLATED — the host-loopback service is NOT on the agent's own loopback.
	if c, err := net.DialTimeout("tcp", target, 2*time.Second); err == nil {
		c.Close()
		report("ISOLATED", false, fmt.Sprintf("direct dial to %s SUCCEEDED (loopback is shared!)", target))
	} else {
		report("ISOLATED", true, fmt.Sprintf("direct dial to %s failed as expected (%v)", target, err))
	}

	if sock == "" {
		report("PROXY-OK", false, "BULKHEAD_EGRESS_SOCK unset — no proxy to test")
		return exitCode(ok)
	}

	// 3. PROXY-OK — the same target IS reachable through the mediated proxy path.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := proxyDial(ctx, sock, target)
	cancel()
	if err == nil {
		conn.Close()
		report("PROXY-OK", true, fmt.Sprintf("%s reachable via the egress proxy (mediated path works)", target))
	} else {
		report("PROXY-OK", false, fmt.Sprintf("%s NOT reachable via proxy (%v)", target, err))
	}

	// 4. PROXY-DENY — a non-allowlisted destination is refused by the proxy.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	c2, err2 := proxyDial(ctx2, sock, denied)
	cancel2()
	switch {
	case errors.Is(err2, errEgressDenied):
		report("PROXY-DENY", true, fmt.Sprintf("%s refused by the proxy allowlist as expected", denied))
	case err2 != nil:
		report("PROXY-DENY", false, fmt.Sprintf("%s refused but not via the allowlist (%v)", denied, err2))
	default:
		c2.Close()
		report("PROXY-DENY", false, fmt.Sprintf("%s was ALLOWED through the proxy (allowlist bypass!)", denied))
	}

	// 5. IOURING — io_uring_setup must be denied (ADR-0033). systemd's @system-service allows
	//    the io_uring family (it's in @aio), so the jail's SystemCallFilter subtracts io_uring_*
	//    by name; the call must hit the unit's SystemCallErrorNumber (EPERM) — never hand back a
	//    ring fd, which would be an I/O channel invisible to the tier's seccomp/ptrace mediation.
	var params [120]byte // sizeof(struct io_uring_params) on x86_64
	fd, _, errno := syscall.Syscall(sysIoUringSetup, 1, uintptr(unsafe.Pointer(&params)), 0)
	switch {
	case errno == syscall.EPERM || errno == syscall.ENOSYS:
		report("IOURING", true, fmt.Sprintf("io_uring_setup denied as expected (%v)", errno))
	case errno == 0:
		syscall.Close(int(fd))
		report("IOURING", false, "io_uring_setup SUCCEEDED — a syscall-invisible I/O channel is reachable!")
	default:
		report("IOURING", false, fmt.Sprintf("io_uring_setup not seccomp-denied (errno %v)", errno))
	}

	return exitCode(ok)
}

// runRomountProbe is the security-review R3 live check (dispatched from main). Under the gVisor
// substrate the two mediated UDS legs are bind-mounted READ-ONLY, so a sandboxed agent cannot remove
// or replace the shared egress.sock — a cross-tier DoS that would deny every other tier its only way
// out. From inside the runsc sandbox it REPORTS the outcome of three writes (the harness judges them
// against the mount mode, so the same binary serves both the ro test and the rw counterfactual):
//
//	ROMOUNT-CONNECT — a connect() to the egress proxy through the UDS (OK|FAIL);
//	ROMOUNT-UNLINK  — unlink(2) of the egress socket (ALLOWED|REFUSED-*) — the literal DoS;
//	ROMOUNT-CREATE  — creating a new entry in the probed leg dir (ALLOWED|REFUSED-*).
//
// Note gVisor reports a read-only-mount write as EACCES/EPERM, not Linux's EROFS — either is a
// refusal that closes the DoS (so the harness accepts any REFUSED-*). CONNECT (egress.sock) and the
// probed dir (BULKHEAD_ROMOUNT_DIR, default = the sock's dir) are decoupled so the rw counterfactual
// can probe the SAME leg dir mounted rw with the sock unset — proving a write there is otherwise
// allowed, hence the ro mount is what refuses it. Always exits 0; the harness owns pass/fail.
func runRomountProbe() int {
	target := envOr("BULKHEAD_PROBE_TARGET", "127.0.0.1:8088")
	sock := os.Getenv("BULKHEAD_EGRESS_SOCK")
	dir := os.Getenv("BULKHEAD_ROMOUNT_DIR")
	if dir == "" && sock != "" {
		dir = filepath.Dir(sock)
	}

	if sock != "" {
		// CONNECT — a mediated connect still works through the (ro) UDS mount.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := proxyDial(ctx, sock, target)
		cancel()
		if err == nil {
			conn.Close()
			fmt.Printf("PROBE ROMOUNT-CONNECT: OK — %s reachable via the egress proxy UDS\n", target)
		} else {
			fmt.Printf("PROBE ROMOUNT-CONNECT: FAIL — %s not reachable (%v)\n", target, err)
		}
		// UNLINK — removing the shared socket is the literal cross-tier DoS. (Skipped when sock is
		// unset, as in the rw counterfactual, so it never deletes the real socket.)
		fmt.Printf("PROBE ROMOUNT-UNLINK: %s — unlink(%s)\n", romountOutcome(os.Remove(sock)), sock)
	}

	// CREATE — planting any new entry in the leg dir (a rogue replacement socket). Non-destructive:
	// the temp file is removed if it was created. UNLINK-of-sock and CREATE both need write on the
	// SAME dir, so CREATE-refused already implies the existing sock cannot be unlinked either.
	if dir != "" {
		probe := filepath.Join(dir, "romount-probe")
		f, err := os.Create(probe)
		if err == nil {
			f.Close()
			_ = os.Remove(probe)
		}
		fmt.Printf("PROBE ROMOUNT-CREATE: %s — create(%s)\n", romountOutcome(err), probe)
	}
	return 0
}

// romountOutcome classifies a write attempt. gVisor surfaces a read-only-mount write as EACCES/EPERM
// (not Linux's EROFS); all three are refusals that close the DoS, so they fold into REFUSED-*.
func romountOutcome(err error) string {
	switch {
	case err == nil:
		return "ALLOWED"
	case errors.Is(err, syscall.EROFS):
		return "REFUSED-EROFS"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return "REFUSED-PERM"
	default:
		return fmt.Sprintf("REFUSED-OTHER(%v)", err)
	}
}

func exitCode(ok bool) int {
	if ok {
		return 0
	}
	return 1
}
