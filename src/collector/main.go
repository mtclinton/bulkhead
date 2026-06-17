// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

// bulkhead-collector: eBPF provenance + an opt-in, fail-open BPF-LSM enforce layer
// (ADR-0004) + a fail-closed self-test.
//
//	bulkhead-collector run            attach the BPF-LSM programs (observe + enforce),
//	                                  pin the policy maps, stream decisions to a
//	                                  hash-chained, Ed25519-signed append-only log.
//	bulkhead-collector selftest       attempt known-forbidden actions; exit non-zero
//	                                  unless every one is denied (gates the services).
//	bulkhead-collector enforce on|off [hook]   flip the per-hook enforce toggle (the
//	                                  kill-switch; default observe). hook defaults to bpf.
//	bulkhead-collector egress set|clear <cgroup> [classes]   set/clear a cgroup's
//	                                  per-agent egress manifest (E2). cgroup is
//	                                  'self', 'id:N', or a cgroup path; classes is a
//	                                  comma list of loopback,linklocal,private,public,
//	                                  other (or any/none). No manifest => unrestricted.
//	bulkhead-collector probe setuid|capset   run as root from a non-TCB cgroup to
//	                                  exercise a privilege gain (regain root / re-raise
//	                                  a capability); exits 1 if E3 denied it (the test).
//	bulkhead-collector probe connect6 <ip6> <port>   AF_INET6 connect() to a (possibly
//	                                  v4-mapped) literal from a non-TCB cgroup to exercise
//	                                  the E2 class gate; exits 1 if E2 denied it (EPERM).
//	bulkhead-collector status         print the enforce toggles + TCB + egress manifests.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// hook ids — MUST match the HOOK_* #defines in provenance.bpf.c.
const (
	hookBPF     uint32 = 0
	hookPtrace  uint32 = 1
	hookConnect uint32 = 3
	hookSetuid  uint32 = 4
	hookCapset  uint32 = 5
)

var hookNames = map[uint32]string{
	hookBPF: "bpf", hookPtrace: "ptrace", hookConnect: "socket_connect",
	hookSetuid: "setuid", hookCapset: "capset",
}

func hookID(name string) (uint32, bool) {
	for id, n := range hookNames {
		if n == name {
			return id, true
		}
	}
	return 0, false
}

// destination classes for the E2 egress manifest — MUST match the DST_* #defines
// in provenance.bpf.c (a connect target's address class, classified in-kernel).
const (
	dstLoopback  uint32 = 1 << 0
	dstLinklocal uint32 = 1 << 1
	dstPrivate   uint32 = 1 << 2
	dstPublic    uint32 = 1 << 3
	dstOther     uint32 = 1 << 4
)

var dstClasses = []struct {
	name string
	bit  uint32
}{
	{"loopback", dstLoopback},
	{"linklocal", dstLinklocal},
	{"private", dstPrivate},
	{"public", dstPublic},
	{"other", dstOther},
}

// parseClasses turns a comma list (or "any"/"none") into a DST_* bitmask.
func parseClasses(s string) (uint32, error) {
	var mask uint32
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		switch tok {
		case "", "none":
			continue
		case "any", "all":
			for _, c := range dstClasses {
				mask |= c.bit
			}
			continue
		}
		matched := false
		for _, c := range dstClasses {
			if c.name == tok {
				mask |= c.bit
				matched = true
				break
			}
		}
		if !matched {
			return 0, fmt.Errorf("unknown class %q (known: loopback,linklocal,private,public,other,any,none)", tok)
		}
	}
	return mask, nil
}

func classNames(mask uint32) string {
	if mask == 0 {
		return "none"
	}
	var parts []string
	for _, c := range dstClasses {
		if mask&c.bit != 0 {
			parts = append(parts, c.name)
		}
	}
	return strings.Join(parts, ",")
}

// resolveCgroupID maps a cgroup spec to its v2 cgroup id (= the cgroup directory
// inode, which is what bpf_get_current_cgroup_id() returns in-kernel).
func resolveCgroupID(spec string) (uint64, error) {
	switch {
	case spec == "self":
		p := selfCgroupPath()
		if p == "" {
			return 0, fmt.Errorf("cannot read /proc/self/cgroup")
		}
		return cgroupIDFromInode(filepath.Join("/sys/fs/cgroup", p))
	case strings.HasPrefix(spec, "id:"):
		var id uint64
		if _, err := fmt.Sscanf(spec, "id:%d", &id); err != nil {
			return 0, fmt.Errorf("bad cgroup id %q: %v", spec, err)
		}
		return id, nil
	case strings.HasPrefix(spec, "/sys/fs/cgroup"):
		return cgroupIDFromInode(spec)
	case strings.HasPrefix(spec, "/"):
		return cgroupIDFromInode(filepath.Join("/sys/fs/cgroup", spec))
	default:
		return 0, fmt.Errorf("cgroup spec must be 'self', 'id:N', or a cgroup path")
	}
}

const pinDir = "/sys/fs/bpf/bulkhead"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "run":
		runCollector()
	case "selftest":
		runSelftest()
	case "enforce":
		cmdEnforce(os.Args[2:])
	case "egress":
		cmdEgress(os.Args[2:])
	case "probe":
		cmdProbe(os.Args[2:])
	case "broker":
		cmdBroker()
	case "delegate":
		cmdDelegate(os.Args[2:])
	case "expand":
		cmdExpand(os.Args[2:])
	case "approve":
		cmdApprove(os.Args[2:])
	case "narrow":
		cmdNarrow(os.Args[2:])
	case "grant-once":
		cmdGrantOnce(os.Args[2:])
	case "ctl":
		cmdControl(os.Args[2:])
	case "attest":
		cmdAttest(os.Args[2:])
	case "gc":
		cmdGC()
	case "verify-audit":
		cmdVerifyAudit(os.Args[2:])
	case "status":
		cmdStatus()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: bulkhead-collector run|selftest|enforce on|off [hook]|egress set|clear <cgroup> [classes]|probe setuid|capset|ptrace|connect6 <ip6> <port>|broker|delegate <child-suffix> <classes>|expand <classes>|approve list|allow <id>|deny <id>|narrow <target> <classes>|grant-once <ptrace|setuid|capset>|clear self|gc|verify-audit <chain.jsonl> [pubkeyhex|@pubfile]|status")
	os.Exit(2)
}

// ---- selftest: fail closed -------------------------------------------------

func runSelftest() {
	failures := 0

	// (a) Egress to a routeable, non-allowlisted address must be denied by the
	// nftables floor. A DROP yields a timeout; EPERM is also a pass; an ESTABLISHED
	// connection is the only failure. At boot before a DHCP lease this passes via
	// ENETUNREACH — the M4 egress check is the authoritative network-up test.
	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second)
	if err == nil {
		conn.Close()
		log.Printf("SELFTEST FAIL: egress to 1.1.1.1:443 succeeded (floor is open)")
		failures++
	} else {
		log.Printf("selftest ok: forbidden egress denied (%v)", err)
	}

	// (b) Writing outside the allowed paths must be denied (ProtectSystem=strict
	// makes /usr read-only for this unit). A successful create is a failure.
	const canary = "/usr/.bulkhead-selftest-canary"
	f, err := os.OpenFile(canary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		f.Close()
		os.Remove(canary)
		log.Printf("SELFTEST FAIL: wrote %s (filesystem confinement is open)", canary)
		failures++
	} else {
		log.Printf("selftest ok: forbidden write denied (%v)", err)
	}

	if failures > 0 {
		log.Fatalf("SELF-TEST FAILED: %d probe(s) not denied — refusing to launch services", failures)
	}
	log.Printf("self-test passed: the floor denies forbidden actions")
}

// ---- enforce / status: control the pinned policy maps ----------------------

func cmdEnforce(args []string) {
	if len(args) < 1 || (args[0] != "on" && args[0] != "off") {
		usage()
	}
	hook := "bpf"
	if len(args) > 1 {
		hook = args[1]
	}
	if _, ok := hookID(hook); !ok {
		log.Fatalf("unknown hook %q (known: bpf, ptrace, socket_connect, setuid, capset)", hook)
	}
	v := "0"
	if args[0] == "on" {
		v = "1"
	}
	// ADR-0016: route the enforce_flags write through the collector control socket so the bpf()
	// is issued from the collector's TCB context. A DIRECT Update here runs in THIS process's
	// cgroup, so once E0 is armed a DISARM from a non-TCB cgroup (the documented `systemctl stop
	// bulkhead-enforce` kill-switch) would be EPERM'd and silently fail. The collector confirms
	// the write; a non-OK reply (collector down / denied) exits non-zero so the unit fails loudly.
	// Retry the control dial: at boot, bulkhead-enforce-egress.service arms E2 with NO
	// wait-broker-tcb gate (E2 has no broker dependency), so its `enforce on socket_connect` can
	// race the collector binding control.sock — a single dial would lose, Fatalf, and silently
	// leave E2 in OBSERVE (per-agent egress unenforced). The operator/soft-disarm path dials once.
	ok, resp := controlRPCRetry("ENFORCE-SET " + hook + " " + v)
	if !ok {
		log.Fatalf("enforce %s %s (control socket unavailable): %s", args[0], hook, resp)
	}
	state := "observe (fail-open)"
	if v == "1" {
		state = "DENY non-TCB"
	}
	log.Printf("enforce %s for hook %q — %s [%s]", args[0], hook, state, resp)
}

// cmdEgress sets or clears a cgroup's per-agent egress manifest (E2). The manifest
// is enforced only when `enforce on socket_connect` is also armed; absent a manifest
// a cgroup is unrestricted (the nftables floor still applies).
func cmdEgress(args []string) {
	if len(args) < 2 || (args[0] != "set" && args[0] != "clear") {
		usage()
	}
	cg, err := resolveCgroupID(args[1])
	if err != nil {
		log.Fatalf("resolve cgroup %q: %v", args[1], err)
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "egress_policy"), nil)
	if err != nil {
		log.Fatalf("open pinned egress_policy (is the collector running?): %v", err)
	}
	defer m.Close()

	if args[0] == "clear" {
		if err := m.Delete(cg); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Fatalf("clear egress_policy: %v", err)
		}
		log.Printf("egress manifest cleared for cgroup %d — unrestricted (nftables floor still applies)", cg)
		return
	}

	if len(args) < 3 {
		log.Fatalf("usage: bulkhead-collector egress set <cgroup> <classes>")
	}
	mask, err := parseClasses(args[2])
	if err != nil {
		log.Fatalf("%v", err)
	}
	if err := m.Update(cg, mask, ebpf.UpdateAny); err != nil {
		log.Fatalf("update egress_policy: %v", err)
	}
	log.Printf("egress manifest for cgroup %d = %s (mask 0x%02x)", cg, classNames(mask), mask)
}

// cmdProbe exercises a real privilege-GAIN primitive so E3 can be verified: run it
// as root from a non-TCB cgroup. It first DROPS privilege (which E3 always allows),
// then tries to REGAIN it (which the kernel permits but E3 denies when armed).
// Prints ALLOWED/DENIED and exits 0 (regain allowed) / 1 (regain denied) / 3 (setup).
func cmdProbe(args []string) {
	// connect6: issue a genuine AF_INET6 connect() to a (possibly v4-mapped) literal from
	// THIS process's cgroup, to verify the E2 egress class gate (classify_dest). The LSM
	// socket_connect hook fires at connect() entry — before the TCP handshake AND before any
	// v6only check — so an E2 denial surfaces as EPERM synchronously. Building the sockaddr
	// from net.IP.To16() keeps a v4-mapped literal (::ffff:a.b.c.d) on AF_INET6 — the exact
	// path a compromised agent would use to dodge a per-class manifest — instead of letting
	// getaddrinfo normalize it to AF_INET. exit 1 = DENIED (EPERM), 0 = ALLOWED by E2 (we do
	// not await handshake completion), 3 = setup error.
	if len(args) >= 1 && args[0] == "connect6" {
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: bulkhead-collector probe connect6 <ip6-literal> <port>")
			os.Exit(2)
		}
		ip := net.ParseIP(args[1])
		if ip == nil || ip.To16() == nil {
			fmt.Printf("PROBE connect6: bad IPv6 literal %q\n", args[1])
			os.Exit(3)
		}
		port, err := strconv.Atoi(args[2])
		if err != nil || port < 1 || port > 65535 {
			fmt.Printf("PROBE connect6: bad port %q\n", args[2])
			os.Exit(3)
		}
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			fmt.Printf("PROBE connect6: socket() failed: %v\n", err)
			os.Exit(3)
		}
		defer unix.Close(fd)
		var sa unix.SockaddrInet6
		copy(sa.Addr[:], ip.To16())
		sa.Port = port
		err = unix.Connect(fd, &sa)
		if errors.Is(err, unix.EPERM) {
			fmt.Printf("PROBE connect6 [%s]:%d DENIED (EPERM — E2 egress class gate)\n", args[1], port)
			os.Exit(1)
		}
		// nil or EINPROGRESS (non-blocking) => E2 PERMITTED the connect; any other errno
		// (ECONNREFUSED/ENETUNREACH/EINVAL...) is a post-permit protocol result — still ALLOWED by E2.
		fmt.Printf("PROBE connect6 [%s]:%d ALLOWED by E2 (connect err=%v)\n", args[1], port, err)
		os.Exit(0)
	}

	// connect4: the AF_INET counterpart — a genuine AF_INET connect() to an IPv4 literal,
	// exercising the AF_INET entry into classify_v4() directly (connect6 with 0.0.0.0 would
	// take the v4-mapped path instead). The discriminating case is 0.0.0.0 (INADDR_ANY),
	// which the kernel rewrites to loopback inside ops->connect, AFTER the LSM hook — so a
	// `public`-but-not-`loopback` agent must see EPERM here. Same exit contract as connect6.
	if len(args) >= 1 && args[0] == "connect4" {
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: bulkhead-collector probe connect4 <ip4-literal> <port>")
			os.Exit(2)
		}
		ip := net.ParseIP(args[1])
		if ip == nil || ip.To4() == nil {
			fmt.Printf("PROBE connect4: bad IPv4 literal %q\n", args[1])
			os.Exit(3)
		}
		port, err := strconv.Atoi(args[2])
		if err != nil || port < 1 || port > 65535 {
			fmt.Printf("PROBE connect4: bad port %q\n", args[2])
			os.Exit(3)
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			fmt.Printf("PROBE connect4: socket() failed: %v\n", err)
			os.Exit(3)
		}
		defer unix.Close(fd)
		var sa unix.SockaddrInet4
		copy(sa.Addr[:], ip.To4())
		sa.Port = port
		err = unix.Connect(fd, &sa)
		if errors.Is(err, unix.EPERM) {
			fmt.Printf("PROBE connect4 %s:%d DENIED (EPERM — E2 egress class gate)\n", args[1], port)
			os.Exit(1)
		}
		// nil or EINPROGRESS (non-blocking) => E2 PERMITTED; any other errno is a post-permit
		// protocol result (ECONNREFUSED/ENETUNREACH/EINVAL...) — still ALLOWED by E2.
		fmt.Printf("PROBE connect4 %s:%d ALLOWED by E2 (connect err=%v)\n", args[1], port, err)
		os.Exit(0)
	}

	if len(args) < 1 || (args[0] != "setuid" && args[0] != "capset" && args[0] != "ptrace") {
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector probe setuid|capset|ptrace|connect4 <ip4> <port>|connect6 <ip6> <port>")
		os.Exit(2)
	}
	// setuid/capset/ptrace are per-thread on Linux; keep the calls on one OS thread.
	runtime.LockOSThread()

	if args[0] == "ptrace" {
		// PTRACE_ATTACH to our OWN child triggers security_ptrace_access_check (E1) — the
		// kernel/Yama permit attaching to a descendant, so a denial here is purely E1. A
		// self-contained probe (no setpriv/su): exit 1 = denied, 0 = allowed, 3 = setup.
		child := exec.Command("/bin/sleep", "10")
		if err := child.Start(); err != nil {
			fmt.Printf("PROBE ptrace: spawn child failed: %v\n", err)
			os.Exit(3)
		}
		pid := child.Process.Pid
		if err := unix.PtraceAttach(pid); err != nil {
			fmt.Printf("PROBE ptrace: attach to child %d DENIED (%v)\n", pid, err)
			_ = child.Process.Kill()
			_, _ = child.Process.Wait()
			os.Exit(1)
		}
		var ws unix.WaitStatus
		_, _ = unix.Wait4(pid, &ws, 0, nil) // reap the attach-stop
		_ = unix.PtraceDetach(pid)
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
		fmt.Printf("PROBE ptrace: attach to child %d ALLOWED\n", pid)
		os.Exit(0)
	}

	if args[0] == "setuid" {
		// Drop euid to 1000 but retain suid=0 (a real escalation primitive). E3
		// allows the drop.
		if err := unix.Setresuid(1000, 1000, 0); err != nil {
			fmt.Printf("PROBE setuid: drop to uid 1000 failed: %v\n", err)
			os.Exit(3)
		}
		// Regain effective root from the retained suid. The kernel permits this;
		// E3 (task_fix_setuid) denies the GAIN when armed.
		if err := unix.Setresuid(0, 0, 0); err != nil {
			fmt.Printf("PROBE setuid: regain root DENIED (%v)\n", err)
			os.Exit(1)
		}
		fmt.Printf("PROBE setuid: regain root ALLOWED (euid=%d)\n", os.Geteuid())
		os.Exit(0)
	}

	// capset: drop CAP_SYS_ADMIN from the effective set (keeping it permitted) — a
	// drop E3 allows — then raise it back, a kernel-permitted GAIN E3 denies.
	const capSysAdmin = 21 // CAP_SYS_ADMIN, word 0 (caps 0..31)
	bit := uint32(1) << capSysAdmin
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	var cur [2]unix.CapUserData
	if err := unix.Capget(&hdr, &cur[0]); err != nil {
		fmt.Printf("PROBE capset: capget failed: %v\n", err)
		os.Exit(3)
	}
	if cur[0].Effective&bit == 0 || cur[0].Permitted&bit == 0 {
		fmt.Printf("PROBE capset: CAP_SYS_ADMIN not held (eff/perm) — cannot probe\n")
		os.Exit(3)
	}
	dropped := cur
	dropped[0].Effective &^= bit // remove from effective only
	if err := unix.Capset(&hdr, &dropped[0]); err != nil {
		fmt.Printf("PROBE capset: drop CAP_SYS_ADMIN failed: %v\n", err)
		os.Exit(3)
	}
	if err := unix.Capset(&hdr, &cur[0]); err != nil { // raise back == the GAIN
		fmt.Printf("PROBE capset: re-raise CAP_SYS_ADMIN DENIED (%v)\n", err)
		os.Exit(1)
	}
	fmt.Printf("PROBE capset: re-raise CAP_SYS_ADMIN ALLOWED\n")
	os.Exit(0)
}

func cmdStatus() {
	ef, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "enforce_flags"), nil)
	if err != nil {
		log.Fatalf("open pinned maps (is the collector running?): %v", err)
	}
	defer ef.Close()
	fmt.Println("enforce toggles (per hook):")
	for id, name := range hookNames {
		var v uint32
		_ = ef.Lookup(id, &v)
		state := "observe"
		if v == 1 {
			state = "ENFORCE"
		}
		fmt.Printf("  %-16s %s\n", name, state)
	}
	if tcb, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "tcb_cgroups"), nil); err == nil {
		defer tcb.Close()
		var key uint64
		var val uint32
		fmt.Println("TCB-allowlisted cgroup ids:")
		it := tcb.Iterate()
		for it.Next(&key, &val) {
			fmt.Printf("  %d\n", key)
		}
	}
	if ep, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "egress_policy"), nil); err == nil {
		defer ep.Close()
		fmt.Println("egress manifests (cgroup -> allowed dest classes):")
		var key uint64
		var val uint32
		it := ep.Iterate()
		any := false
		for it.Next(&key, &val) {
			fmt.Printf("  %-20d %s\n", key, classNames(val))
			any = true
		}
		if !any {
			fmt.Println("  (none — every cgroup unrestricted; nftables floor applies)")
		}
	}
	if gm, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "grant_once"), nil); err == nil {
		defer gm.Close()
		fmt.Println("one-shot grants (cgroup,hook -> remaining; ADR-0011):")
		var k bpfGrantKey
		var v bpfGrantVal
		it := gm.Iterate()
		any := false
		now := monotonicNs()
		for it.Next(&k, &v) {
			name := hookNames[k.Hook]
			if name == "" {
				name = fmt.Sprintf("hook%d", k.Hook)
			}
			ttl := "none"
			if v.ExpireNs != 0 {
				if now != 0 && v.ExpireNs > now {
					ttl = fmt.Sprintf("%ds", (v.ExpireNs-now)/1_000_000_000)
				} else {
					ttl = "expired"
				}
			}
			fmt.Printf("  cg=%-18d %-8s count=%d ttl=%s\n", k.Cgid, name, v.Count, ttl)
			any = true
		}
		if !any {
			fmt.Println("  (none)")
		}
	}
}

// ---- collector: provenance + opt-in enforce --------------------------------

func runCollector() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	// Fresh pin dir each run: a restart resets enforce to default-observe (fail-safe).
	_ = os.RemoveAll(pinDir)
	if err := os.MkdirAll(pinDir, 0o700); err != nil {
		log.Fatalf("mkdir pin dir %s: %v", pinDir, err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("load bpf objects: %v", err)
	}
	defer objs.Close()

	// Observe-only provenance on socket_connect (unchanged verdict).
	lObs, err := link.AttachLSM(link.LSMOptions{Program: objs.ProvSocketConnect})
	if err != nil {
		log.Fatalf("attach lsm/socket_connect (is bpf in the active LSM list?): %v", err)
	}
	defer lObs.Close()

	// Opt-in enforce on bpf() — attached but default-observe (enforce_flags empty).
	lEnf, err := link.AttachLSM(link.LSMOptions{Program: objs.EnforceBpf})
	if err != nil {
		log.Fatalf("attach lsm/bpf: %v", err)
	}
	defer lEnf.Close()

	// E1: opt-in enforce on ptrace_access_check (deny agents ptracing others).
	lEnfPt, err := link.AttachLSM(link.LSMOptions{Program: objs.EnforcePtrace})
	if err != nil {
		log.Fatalf("attach lsm/ptrace_access_check: %v", err)
	}
	defer lEnfPt.Close()

	// E3: opt-in enforce on privilege gains — task_fix_setuid (regaining root) and
	// capset (raising caps). Both default-observe; allow drops always.
	lEnfSu, err := link.AttachLSM(link.LSMOptions{Program: objs.EnforceSetuid})
	if err != nil {
		log.Fatalf("attach lsm/task_fix_setuid: %v", err)
	}
	defer lEnfSu.Close()
	lEnfCap, err := link.AttachLSM(link.LSMOptions{Program: objs.EnforceCapset})
	if err != nil {
		log.Fatalf("attach lsm/capset: %v", err)
	}
	defer lEnfCap.Close()

	// Populate the TCB allowlist (collector + init/root cgroup) BEFORE anything could
	// arm enforce, so the privileged loaders are never denied.
	for _, cg := range tcbCgroupIDs() {
		if err := objs.TcbCgroups.Update(cg, uint32(1), ebpf.UpdateAny); err != nil {
			log.Printf("tcb allowlist update (cgid %d): %v", cg, err)
		}
	}

	// Pin the policy maps so the `enforce`/`status` subcommands (separate processes)
	// can reach the running collector's maps. Default observe: enforce_flags stays 0.
	if err := objs.EnforceFlags.Pin(filepath.Join(pinDir, "enforce_flags")); err != nil {
		log.Fatalf("pin enforce_flags: %v", err)
	}
	if err := objs.TcbCgroups.Pin(filepath.Join(pinDir, "tcb_cgroups")); err != nil {
		log.Fatalf("pin tcb_cgroups: %v", err)
	}
	// E2: pin the per-agent egress manifest map for the `egress`/`status` subcommands.
	if err := objs.EgressPolicy.Pin(filepath.Join(pinDir, "egress_policy")); err != nil {
		log.Fatalf("pin egress_policy: %v", err)
	}
	// ADR-0011: pin the one-shot E1/E3 grant map for the broker `grant-once` action +
	// `status`. RemoveAll above wiped any prior grants on restart (the fail-safe: a
	// restart resets enforce to observe AND drops outstanding grants).
	if err := objs.GrantOnce.Pin(filepath.Join(pinDir, "grant_once")); err != nil {
		log.Fatalf("pin grant_once: %v", err)
	}

	// ADR-0016: pre-register the broker's cgroup as TCB if it already exists, so a boot-time E0
	// arm finds it. The broker ALSO self-requests via the control socket at its startup, and
	// reconcileTCB re-establishes it each GC pass; all three resolve the broker cgid ONLY from
	// the fixed brokerCgroupPath, never from a caller (no arbitrary-TCB-register primitive).
	if bid, err := cgroupIDFromInode(brokerCgroupPath); err == nil {
		if err := objs.TcbCgroups.Update(bid, uint32(1), ebpf.UpdateAny); err != nil {
			log.Printf("broker tcb pre-register (cgid %d): %v", bid, err)
		}
	}
	// Open the signed audit chains BEFORE serving anything that appends to them. The collector
	// writes TWO chains (both domain-tagged + Ed25519-signed with the sealed seed): the
	// single-writer kernel-verdict chain (the ringbuf loop), and — ADR-0017 — a separate `control`
	// chain for the control socket's authority-changing WRITES, so every per-agent manifest write /
	// broker TCB registration / enforce toggle is tamper-evident, not merely logged.
	al, err := openAuditLog("collector", "provenance.jsonl")
	if err != nil {
		log.Fatalf("audit log: %v", err)
	}
	defer al.Close()
	controlAL, err = openAuditLog("control", "control.jsonl")
	if err != nil {
		log.Fatalf("control audit log: %v", err)
	}
	defer controlAL.Close()

	// ADR-0016: the control socket — the bpf()-WRITE chokepoint for non-TCB callers (the agent
	// +ExecStartPre manifest write + clears, and the broker's TCB self-registration). Started AFTER
	// the control chain is open (no write is ever served unsigned). The collector (TCB, E0-exempt)
	// does every Update on a caller's behalf, so those writes survive E0-armed; broker/agents order
	// After=collector, so the socket exists before they connect.
	controlLn, err := controlListener()
	if err != nil {
		log.Fatalf("control listen: %v", err)
	}
	go acceptLoop(controlLn, handleControlConn)

	log.Printf("collector running: observe+enforce attached (bpf,ptrace,socket_connect,setuid,capset; default observe), audit at %s (+ control chain), signer %s", al.path, al.pubHex())

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf reader: %v", err)
	}
	defer rd.Close()

	// ADR-0012: TCB-context GC of dead-agent per-agent map entries. Runs in THIS process
	// (cgroup already in tcb_cgroups above), so its bpf() Delete survives E0-armed — the
	// cleanup the agent's own E0-blockable ExecStopPost cannot do, and it also reclaims
	// agents that crashed and skipped ExecStopPost entirely.
	gcStop := make(chan struct{})
	go gcLoop(gcStop)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-stop; close(gcStop); rd.Close() }()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		b := rec.RawSample
		if len(b) < 40 {
			continue
		}
		// bpfEvent: cgroup_id u64@0, pid u32@8, comm[16]@12, hook u32@28,
		// decision u32@32, mode u32@36.
		mode := binary.LittleEndian.Uint32(b[36:40])
		ev := provEvent{
			CgroupID: binary.LittleEndian.Uint64(b[0:8]),
			PID:      binary.LittleEndian.Uint32(b[8:12]),
			Comm:     string(bytes.TrimRight(b[12:28], "\x00")),
			Hook:     hookNames[binary.LittleEndian.Uint32(b[28:32])],
			Decision: decisionName(binary.LittleEndian.Uint32(b[32:36]), mode),
			Mode:     modeName(mode),
		}
		if ev.Hook == "" {
			ev.Hook = "unknown"
		}
		if err := al.append(ev); err != nil {
			log.Printf("audit append: %v", err)
		}
	}
}

func decisionName(decision, mode uint32) string {
	if decision == 0 {
		return "allowed"
	}
	if mode == 1 {
		return "denied"
	}
	return "would-deny"
}

func modeName(mode uint32) string {
	if mode == 1 {
		return "enforce"
	}
	return "observe"
}

// tcbCgroupIDs returns the cgroup ids of the collector itself and the root cgroup.
// bpf_get_current_cgroup_id() returns the v2 cgroup's kernfs id, which equals the
// inode of the cgroup directory under /sys/fs/cgroup.
func tcbCgroupIDs() []uint64 {
	var ids []uint64
	if id, err := cgroupIDFromInode("/sys/fs/cgroup"); err == nil {
		ids = append(ids, id) // root cgroup (PID-1 / system-level loaders)
	}
	if p := selfCgroupPath(); p != "" {
		if id, err := cgroupIDFromInode(filepath.Join("/sys/fs/cgroup", p)); err == nil {
			ids = append(ids, id) // the collector's own cgroup
		}
	}
	return ids
}

func selfCgroupPath() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		// v2 unified line: "0::/system.slice/bulkhead-collector.service"
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::")
		}
	}
	return ""
}

func cgroupIDFromInode(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// ---- tamper-evident audit log ----------------------------------------------

type provEvent struct {
	CgroupID uint64
	PID      uint32
	Comm     string
	Hook     string
	Decision string // allowed | denied | would-deny
	Mode     string // observe | enforce
}

// durableFile is the subset of *os.File that append() uses. It is an interface (not *os.File directly) so
// tests can inject I/O faults — a Write or Sync that errors — to exercise the transactional-append rollback
// in append(). *os.File satisfies it, so production behavior is unchanged. Mirrors router/audit.go.
type durableFile interface {
	Write([]byte) (int, error)
	Sync() error
	Truncate(int64) error
	Stat() (os.FileInfo, error)
	Close() error
}

type auditLog struct {
	mu       sync.Mutex  // serialize append: the broker decision chain (brokerAL) is appended from concurrent
	f        durableFile // connection-handler goroutines (recordDecision/recordNarrow) — mirrors router/audit.go.
	path     string
	priv     ed25519.PrivateKey
	prevHash []byte
	seq      uint64
	domain   string // F4: per-chain domain ("collector"|"broker") bound into canonical()
	// ADR-0040 segment rotation (all guarded by a.mu, set once in openAuditLog except segNext, bumped by
	// rotate()). dir/base locate the chain; rotateBytes>0 enables rotation; segKeep is the retained window.
	dir         string
	base        string
	rotateBytes int64
	segKeep     int
	segNext     uint64
}

type auditRecord struct {
	Seq      uint64 `json:"seq"`
	TS       int64  `json:"ts"`
	CgroupID uint64 `json:"cgroup_id"`
	PID      uint32 `json:"pid"`
	Comm     string `json:"comm"`
	Hook     string `json:"hook"`
	Decision string `json:"decision"`
	Mode     string `json:"mode"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
	Sig      string `json:"sig"`
}

func openAuditLog(domain, filename string) (*auditLog, error) {
	dir := "/var/lib/bulkhead/audit"
	if d := os.Getenv("BULKHEAD_AUDIT_DIR"); d != "" {
		dir = d
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	chainPath := filepath.Join(dir, filename)
	// Repair an un-acknowledged partial final record before continuing the chain. A power-loss can
	// leave append()'s "line\n" written WITHOUT its terminating '\n'; the verifier tolerates that
	// fragment only while it stays last, but O_APPEND would FUSE the next boot's first record onto it
	// ({frag...{seq:1...}\n), putting a malformed two-records-on-one-line MID-chain once a second
	// record follows — false-bricking verify-audit (and forcing a RAUC rollback) two boots after one
	// unclean shutdown. Truncating the un-acked tail restores "a sequence of newline-terminated
	// records" (mirroring append()'s own rollback). Best-effort: a failure degrades to the prior
	// behaviour, never blocks the open. (Cross-cutting audit 2026-06-16, torn-tail finding.)
	if err := repairTornTail(chainPath); err != nil {
		log.Printf("audit: torn-tail repair (%s): %v", chainPath, err)
	}
	// F5 (composed review): continue the hash chain ACROSS boots — the new boot's first
	// record links to the prior boot's LAST hash, not a fresh zero. So deleting a whole
	// middle per-boot subchain breaks the linkage and verify-audit catches it (re-anchoring
	// at every seq=1/zero-prev let a complete-subchain deletion pass before). Genesis (no /
	// empty / unreadable-tail chain) starts at zero; a corrupt tail then mislinks and is
	// caught by the verifier's continuity check rather than silently masked.
	// Seed the cross-boot prevHash (F5) from the chain TIP, which after a rotation lives in the live file
	// OR — in the rename->first-append window — the newest sealed segment (lastChainTip, ADR-0040), never a
	// spurious genesis that would fork the chain.
	prev := make([]byte, sha256.Size)
	if h := lastChainTip(dir, filename); h != nil {
		prev = h
	}
	f, err := os.OpenFile(chainPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	priv, err := loadSigningKey()
	if err != nil {
		f.Close()
		return nil, err
	}
	rotateBytes, segKeep := auditSegmentConfig()
	a := &auditLog{
		f: f, path: f.Name(), priv: priv, prevHash: prev, domain: domain,
		dir: dir, base: filename, rotateBytes: rotateBytes, segKeep: segKeep, segNext: nextSegNum(dir, filename),
	}
	// F5: export the public key beside the chain so it can be verified OFFLINE (ship the
	// log + this pubkey off-box; `verify-audit <chain> @audit-pub.txt`). Best-effort — the
	// chain itself is the critical path, and the on-box boot gate verifies against the
	// SEALED seed (which an attacker cannot rewrite to match a forged chain), not this file.
	if err := os.WriteFile(filepath.Join(dir, "audit-pub.txt"), []byte(a.pubHex()+"\n"), 0o644); err != nil {
		log.Printf("audit: export public key: %v", err)
	}
	return a, nil
}

// loadSigningKey reads a 32-byte Ed25519 seed from the systemd credential dir. On the
// appliance the seed is a TPM-sealed credential (ADR-0008) that systemd unseals into
// CREDENTIALS_DIRECTORY via LoadCredentialEncrypted; a stable seed => a stable audit
// identity across reboots, and a tampered/unsatisfied PCR policy makes systemd refuse to
// pass it (the unit fails to start). Absent a credential it falls back to an ephemeral
// per-boot key so non-TPM dev/Buildroot smoke tests still run — UNLESS
// BULKHEAD_REQUIRE_SEALED_KEY=1, in which case it fails closed rather than ever signing
// the provenance/decision chain with a throwaway key.
func loadSigningKey() (ed25519.PrivateKey, error) {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		if seed, err := os.ReadFile(filepath.Join(dir, "audit-seed")); err == nil && len(seed) >= ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]), nil
		}
	}
	if os.Getenv("BULKHEAD_REQUIRE_SEALED_KEY") == "1" {
		return nil, fmt.Errorf("sealed audit key unavailable (CREDENTIALS_DIRECTORY=%q): refusing to sign with an ephemeral key",
			os.Getenv("CREDENTIALS_DIRECTORY"))
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func (a *auditLog) pubHex() string {
	return hex.EncodeToString(a.priv.Public().(ed25519.PublicKey))
}

// canonical is a fixed-order, length-prefixed binary encoding of exactly the
// chained fields — never json.Marshal, whose key order/whitespace is unstable.
func canonical(r auditRecord, prev []byte, domain string) []byte {
	var b bytes.Buffer
	var u8 [8]byte
	put := func(v uint64) { binary.BigEndian.PutUint64(u8[:], v); b.Write(u8[:]) }
	putStr := func(s string) { put(uint64(len(s))); b.WriteString(s) }
	// F4 (composed review): a per-chain DOMAIN tag bound into the signed hash. The collector
	// and broker share one sealed seed; without this tag a record signed for one chain
	// verifies as a valid record of the other, so a /data attacker could transplant
	// validly-signed subchains between them. The domain is supplied by the VERIFIER (which
	// knows which chain it is checking), NOT read from the record, so a transplant fails.
	putStr(domain)
	put(r.Seq)
	put(uint64(r.TS))
	put(r.CgroupID)
	put(uint64(r.PID))
	putStr(r.Comm)
	putStr(r.Hook)
	putStr(r.Decision)
	putStr(r.Mode)
	put(uint64(len(prev)))
	b.Write(prev)
	return b.Bytes()
}

// lastChainHash returns the decoded Hash of the last well-formed record in the chain file,
// or nil (genesis / unreadable). Used to continue the hash chain across boots (F5).
// repairTornTail discards an un-acknowledged partial final record — bytes after the last newline,
// left by a power-loss between append()'s write and its '\n'. It restores the invariant that the
// file is a sequence of newline-terminated records, so the next append starts a fresh line and
// cannot fuse onto the fragment. A clean file (empty, or ending in '\n') is untouched; a file with
// no newline at all truncates to 0 (the whole partial first record was never committed).
func repairTornTail(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(b) == 0 || b[len(b)-1] == '\n' {
		return nil
	}
	keep := int64(bytes.LastIndexByte(b, '\n') + 1) // 0 when there is no newline
	return os.Truncate(path, keep)
}

func lastChainHash(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		ln := bytes.TrimSpace(lines[i])
		if len(ln) == 0 {
			continue
		}
		var r auditRecord
		if json.Unmarshal(ln, &r) != nil {
			return nil
		}
		h, err := hex.DecodeString(r.Hash)
		if err != nil || len(h) != sha256.Size {
			return nil
		}
		return h
	}
	return nil
}

// --- ADR-0040: bounded-retention segment rotation -------------------------------------------------
// The signed chains share a fixed 100 MB /data partition; an unbounded append-only log lets one noisy
// tier (egress) fill /data and starve every other chain into a fail-closed append DoS (security-review
// R9). Rotation seals the live file into a numbered segment (<live>.NNNNNN) once it reaches a byte
// threshold, keeps a bounded window of segments, and prunes older ones — capping each chain at
// (segKeep+1)*rotateBytes. The seam is link-continuous (prevHash/seq are NOT reset across a rotation),
// so verifySegmentedChain checks the retained segments + live file as ONE chain. segmentPath/listSegments
// MUST stay byte-identical across src/collector, src/proxy, src/router (the collector's verifier reads the
// segments the proxy/router produce); the "%s.%06d" naming is the shared contract.

// segmentPath is the sealed-segment path for number n: <dir>/<base>.NNNNNN, zero-padded width-6 so the
// lexical order of the names equals their numeric order (6 digits => up to 999999 segments per chain).
func segmentPath(dir, base string, n uint64) string {
	return filepath.Join(dir, fmt.Sprintf("%s.%06d", base, n))
}

// listSegments returns the existing sealed-segment numbers for <dir>/<base>, ascending. A sibling counts
// as a segment IFF its name is exactly base + "." + an all-digit suffix — so the live file, audit-pub.txt,
// a *.tmp, or another chain's files in a shared dir (control.jsonl beside provenance.jsonl) are excluded.
func listSegments(dir, base string) []uint64 {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	prefix := base + "."
	var nums []uint64
	for _, e := range ents {
		if e.IsDir() {
			continue // a sealed segment is always a regular file; never try to verify a directory fd
		}
		name := e.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suf := name[len(prefix):]
		if suf == "" || strings.TrimLeft(suf, "0123456789") != "" {
			continue // not an all-digit suffix
		}
		n, err := strconv.ParseUint(suf, 10, 64)
		if err != nil {
			continue
		}
		nums = append(nums, n)
	}
	sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
	return nums
}

// nextSegNum returns the number the next sealed segment should get: one past the highest existing segment
// (so a box that rotated, lost power, and rebooted never reuses a number or overwrites signed history), or
// 1 on a chain that has never rotated.
func nextSegNum(dir, base string) uint64 {
	segs := listSegments(dir, base)
	if len(segs) == 0 {
		return 1
	}
	return segs[len(segs)-1] + 1
}

// lastChainTip returns the chain's current tip (last well-formed record hash): the LIVE file's tip, or —
// if the live file is empty/absent (the rename->first-append window after a rotate, or a rotate that
// crashed before its first new record) — the newest non-empty sealed segment's tip, else nil (genesis).
// Used to seed the cross-boot prevHash (F5) and to bind the attest HEADs (ADR-0025) so a quote taken in
// that window binds the newest-segment tip, not a spurious genesis. Per-file tolerance mirrors lastChainHash.
func lastChainTip(dir, base string) []byte {
	if h := lastChainHash(filepath.Join(dir, base)); h != nil {
		return h
	}
	segs := listSegments(dir, base)
	for i := len(segs) - 1; i >= 0; i-- {
		if h := lastChainHash(segmentPath(dir, base, segs[i])); h != nil {
			return h
		}
	}
	return nil
}

// auditSegmentConfig reads the rotation knobs from the environment (ADR-0040). rotateBytes is 0 (rotation
// DISABLED — the pre-R9 single-file behaviour, kept for dev/Buildroot/tests) unless
// BULKHEAD_AUDIT_SEGMENT_BYTES is a positive integer; the appliance *-data.conf drop-ins set it. segKeep is
// the number of sealed segments retained besides the live file (default 1, clamped to a MINIMUM of 1: the
// verifier needs >=1 retained segment as the post-prune on-box anchor, and it keeps the live file always
// linking to a present segment's tip — see verifySegmentedChain). Each chain is bounded at
// (segKeep+1)*rotateBytes on disk (+ <1 record of slack per segment). APPLIANCE BUDGET INVARIANT: Σ over
// the chains of (segKeep+1)*rotateBytes must stay below the /data partition (100 MB) — at 8 MiB / keep=1
// the five chains use 5*(1+1)*8 = 80 MiB.
func auditSegmentConfig() (rotateBytes int64, segKeep int) {
	segKeep = 1
	if v := os.Getenv("BULKHEAD_AUDIT_SEGMENT_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			rotateBytes = n
		}
	}
	if v := os.Getenv("BULKHEAD_AUDIT_SEGMENTS_KEEP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			segKeep = n // a value < 1 is ignored: keep the safe default of 1
		}
	}
	return rotateBytes, segKeep
}

// rotate seals the current live file as the next numbered segment and reopens an empty live file, WITHOUT
// resetting a.prevHash/a.seq — so the first record in the fresh live file links to the sealed segment's tip
// and CONTINUES the seq (the seam is link-continuous; verifySegmentedChain proves it via the existing
// prev_hash check). It then prunes segments older than the retention window. Called from append() under
// a.mu when the live file reaches rotateBytes.
//
// R1 (the critical invariant): rotation must NEVER convert a fill into the fail-closed append DoS R9 exists
// to remove. So rotate() ALWAYS leaves a.f a usable handle: on Sync/Rename failure a.f is the unchanged,
// still-open live file; on a reopen failure after a successful rename it un-renames so the old fd is
// reachable as the live file again. append() treats any returned error as "log and keep writing the current
// file", re-attempting the cap next append. A failed PRUNE is non-fatal (logged).
func (a *auditLog) rotate() error {
	if err := a.f.Sync(); err != nil {
		return err // a.f still open on the live file; append continues on it (R1)
	}
	sealed := segmentPath(a.dir, a.base, a.segNext)
	if err := os.Rename(a.path, sealed); err != nil {
		return err // live file unmoved, a.f still open on it; append continues (R1)
	}
	// The live NAME is now free; the old fd (a.f) still writes the sealed inode. Open a fresh empty live
	// file at a.path and swap to it BEFORE closing the old fd, so a.f is never observed as a closed handle.
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		// Could not create the new live file. Un-rename so a.f's inode is reachable as the live file again (R1).
		if rerr := os.Rename(sealed, a.path); rerr != nil {
			log.Printf("audit: rotate reopen failed AND un-rename failed (%s): %v / %v", a.path, err, rerr)
		}
		return err
	}
	old := a.f
	a.f = f
	a.segNext++
	if cerr := old.Close(); cerr != nil {
		log.Printf("audit: rotate: closing sealed segment %s: %v", sealed, cerr)
	}
	a.pruneSegments()
	return nil
}

// pruneSegments unlinks sealed segments older than the retention window (keeps the newest segKeep). This is
// the step that bounds /data — and the step that moves on-box tamper-detection of the PRUNED records
// off-box (ADR-0040 detection-boundary trade). Best-effort and logged: a failed unlink NEVER fails an
// append (R1); at worst the footprint cap is exceeded transiently and re-attempted on the next rotation.
func (a *auditLog) pruneSegments() {
	segs := listSegments(a.dir, a.base)
	if len(segs) <= a.segKeep {
		return
	}
	for _, n := range segs[:len(segs)-a.segKeep] {
		if err := os.Remove(segmentPath(a.dir, a.base, n)); err != nil {
			log.Printf("audit: prune segment %06d: %v", n, err)
		}
	}
}

func (a *auditLog) append(ev provEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	nextSeq := a.seq + 1 // a LOCAL: a.seq is not advanced until the write+sync below fully succeed
	r := auditRecord{
		Seq: nextSeq, TS: time.Now().UnixNano(),
		CgroupID: ev.CgroupID, PID: ev.PID, Comm: ev.Comm, Hook: ev.Hook,
		Decision: ev.Decision, Mode: ev.Mode,
		PrevHash: hex.EncodeToString(a.prevHash),
	}
	// Coerce the chained string fields to valid UTF-8 BEFORE signing. json.Marshal replaces ill-formed
	// UTF-8 with U+FFFD on write, so a raw-byte signature over invalid UTF-8 (e.g. a non-UTF-8 process
	// Comm, or an untrusted client field) would never re-verify after the JSON round-trip and verify-audit
	// would fail the boot gate CLOSED on a self-inconsistent record. Coercing here (not in canonical())
	// keeps canonical() byte-identical across modules; for valid UTF-8 it is a no-op (the golden is unchanged).
	r.Comm = strings.ToValidUTF8(r.Comm, "�")
	r.Hook = strings.ToValidUTF8(r.Hook, "�")
	r.Decision = strings.ToValidUTF8(r.Decision, "�")
	r.Mode = strings.ToValidUTF8(r.Mode, "�")
	sum := sha256.Sum256(canonical(r, a.prevHash, a.domain))
	r.Hash = hex.EncodeToString(sum[:])
	r.Sig = hex.EncodeToString(ed25519.Sign(a.priv, sum[:]))

	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	// TRANSACTIONAL append (mirrors router/audit.go): capture the pre-append EOF, and on ANY Write/Sync
	// failure truncate the partial/unacked tail back to it (a.mu makes EOF a stable rollback point).
	// Combined with advancing a.seq/a.prevHash ONLY on full success, the on-disk chain always ends at the
	// last fully-synced record — never a gapped seq (a left-advanced a.seq with no record) nor a forked
	// prev_hash (a durable record the in-memory tip skipped) — so one transient I/O error (ENOSPC/EIO) is
	// retried cleanly instead of bricking the next boot's fail-closed verify-audit gate (verify.go).
	fi, err := a.f.Stat()
	if err != nil {
		return err
	}
	off := fi.Size()
	// ADR-0040: seal the live file into a segment once it reaches the threshold, BEFORE writing this record
	// (so each record lands whole in one file). The record links to a.prevHash, which rotate() preserves, so
	// it becomes the link-continuous first record of the fresh live file. R1: a rotation error must not fail
	// the append — keep writing the current file and re-attempt the cap next time.
	if a.rotateBytes > 0 && off >= a.rotateBytes {
		if rerr := a.rotate(); rerr != nil {
			log.Printf("audit: segment rotation failed (continuing on current file): %v", rerr)
		} else if nfi, serr := a.f.Stat(); serr == nil {
			off = nfi.Size() // the fresh live file (0 bytes) is the new transactional rollback point
		} else {
			return serr
		}
	}
	if _, err := a.f.Write(append(line, '\n')); err != nil {
		a.rollback(off)
		return err
	}
	if err := a.f.Sync(); err != nil {
		a.rollback(off)
		return err
	}
	a.seq = nextSeq // commit the in-memory tip ONLY now that the record is durable
	a.prevHash = sum[:]
	return nil
}

// rollback drops any bytes written past off (the pre-append EOF) so a failed/partial record never strands
// on disk to gap or fork the chain; append() leaves a.seq/a.prevHash uncommitted, so a clean retry
// re-appends from off. Best-effort: a Truncate failure is itself a hard I/O fault and is logged, not fatal.
func (a *auditLog) rollback(off int64) {
	if err := a.f.Truncate(off); err != nil {
		log.Printf("audit: rollback truncate to %d: %v", off, err)
	}
}

func (a *auditLog) Close() error { return a.f.Close() }
