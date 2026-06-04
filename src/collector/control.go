// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

// ADR-0016: the collector control socket — the bpf()-WRITE chokepoint for non-TCB callers.
//
// Under E0 (lsm/bpf deny) armed, ONLY a TCB cgroup may issue bpf(). Two map-write sites used to
// run bpf() from a NON-TCB cgroup, which made the full E0-E3 stack un-armable alongside
// delegation: (1) the broker self-registering into tcb_cgroups, and (2) a jailed agent's
// +ExecStartPre writing its own egress manifest. Both now connect to this socket, and the
// COLLECTOR — already TCB, E0-exempt, the single map owner — performs the Update from its own
// context, so E0 can stay armed end-to-end while delegation/EXPAND/grant-once/agent-launch work.
//
// Every caller is attested TWICE from the kernel, NEVER from the request body: SO_PEERCRED (uid
// must be 0) AND SO_PEERPIDFD (pidfd -> pid -> /proc/<pid>/cgroup, pinned against recycle). The
// verb decides WHICH cgid is written: self-verbs write the kernel-attested SELF cgid (and only
// for a real agent-slice cgroup, and only egress_policy/grant_once — never tcb_cgroups); the
// broker-register verb takes NO target and registers ONLY the cgid the collector itself stats
// from the fixed brokerCgroupPath. There is therefore no verb that elevates a caller-named cgroup.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const controlSockPath = "/run/bulkhead/control.sock"

// agentCgroupRe matches the kernel-attested cgroup PATH of a real bulkhead agent jail: a single
// agent-INSTANCE leaf (the @-marker as a real path component, no trailing sub-cgroup), optionally
// nested under /bulkhead.slice. Anchored (^…$) so a substring/embedded marker cannot pass —
// closing the ADR-0016-review C1 gap where strings.Contains admitted a crafted path like
// /…/bulkhead-agent@worker.service/payload.scope or /user.slice/bulkhead-agent.slice/…@x.service.
var agentCgroupRe = regexp.MustCompile(`^(/bulkhead\.slice)?/bulkhead-agent\.slice/bulkhead-agent@[^/]+\.service$`)

// isAgentCgroup reports whether a kernel-attested cgroup PATH is a real bulkhead agent jail. Used
// both for the control self-verb gate (the body never names a cgroup; the cgid is the attested
// caller's) and the broker's delegation gate. PURE so it is unit-testable without a kernel.
func isAgentCgroup(cgPath string) bool {
	return agentCgroupRe.MatchString(cgPath)
}

// isBrokerCaller reports whether a kernel-attested cgroup PATH is EXACTLY the broker unit's
// cgroup — string-equal after Clean (not prefix/substring/traversal), so a nested or sibling
// cgroup can never pass and drive a TCB registration. PURE / unit-testable.
func isBrokerCaller(cgPath string) bool {
	rel := strings.TrimPrefix(brokerCgroupPath, "/sys/fs/cgroup")
	return filepath.Clean(cgPath) == filepath.Clean(rel)
}

// controlMu serializes the collector-side pinned-map writes issued on behalf of control-socket
// callers. Short, non-nested, and collector-process-local — never held across the broker's
// egressMu/launchMu/grantMu (a different process), so there is no cross-process lock inversion.
// It ALSO serializes the control-chain audit appends (recordControl), which auditLog does not
// internally lock — every write verb holds it across both the map Update and the append.
var controlMu sync.Mutex

// controlAL is the collector's CONTROL audit chain (ADR-0017): a separate, domain-tagged,
// Ed25519-signed chain for the control socket's authority-changing WRITES, so every per-agent
// manifest write / broker TCB registration / enforce toggle is tamper-evident — not just logged.
// Opened in runCollector BEFORE the control acceptLoop, so no write is ever served unsigned.
var controlAL *auditLog

// recordControl appends one signed record to the control chain. Called by the write verbs AFTER
// auth, under controlMu (so appends are serialized). Overloads provEvent's 6 fields like the
// broker's recordDecision: cgroup=the affected cgid, hook=the verb, decision=ok|err, mode=detail.
// Auth REJECTIONS are NOT chained (no authority changed, and the 0660-root socket is not
// agent-reachable so a rejected attempt is a misconfigured-root event, log.Printf'd not signed).
func recordControl(hook, comm, decision, mode string, cgID uint64) {
	if controlAL == nil {
		return
	}
	if len(comm) > 16 {
		comm = comm[:16]
	}
	if err := controlAL.append(provEvent{CgroupID: cgID, Comm: comm, Hook: hook, Decision: decision, Mode: mode}); err != nil {
		log.Printf("control: AUDIT APPEND FAILED for %s %s: %v", hook, decision, err)
	}
}

// controlListener creates the control socket (0660 root:root). /run/bulkhead is created early by
// bulkhead-broker.socket's RuntimeDirectory and is in the collector's ReadWritePaths; the MkdirAll
// is a best-effort no-op for that normal case.
func controlListener() (net.Listener, error) {
	_ = os.MkdirAll(filepath.Dir(controlSockPath), 0o755)
	_ = os.Remove(controlSockPath)
	ln, err := net.Listen("unix", controlSockPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(controlSockPath, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// handleControlConn serves one control request. Attest uid (SO_PEERCRED) + cgroup (SO_PEERPIDFD)
// from the kernel, read one verb line, dispatch. A slow/hostile peer cannot wedge the loop
// (deadline + bounded read); an unknown verb is a clean ERR.
func handleControlConn(conn net.Conn) {
	defer conn.Close()
	// 20s: most verbs are sub-millisecond map ops, but the ADR-0019 attest verbs do TPM
	// extend/quote (+ the RC_RETRY resubmit loop) which can take a beat. The socket is 0660
	// root-only, so a slow peer holding the conn is not an agent-reachable DoS vector.
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	reply := func(s string) { fmt.Fprintln(conn, s) }

	if uid, ok := peerUID(conn); !ok || uid != 0 {
		reply("ERR not-root")
		return
	}
	cgID, cgPath, err := peerParentCgID(conn)
	if err != nil {
		reply("ERR peer-auth")
		return
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		reply("ERR read")
		return
	}
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) == 0 {
		reply("ERR protocol")
		return
	}
	switch f[0] {
	case "EGRESS-SET-SELF":
		ctlEgressSetSelf(reply, cgID, cgPath, f)
	case "EGRESS-CLEAR-SELF":
		ctlEgressClearSelf(reply, cgID, cgPath)
	case "GRANT-CLEAR-SELF":
		ctlGrantClearSelf(reply, cgID, cgPath)
	case "TCB-REGISTER-BROKER":
		ctlTcbRegisterBroker(reply, cgPath)
	case "WAIT-BROKER-TCB":
		ctlWaitBrokerTCB(reply)
	case "ENFORCE-SET":
		ctlEnforceSet(reply, cgPath, f)
	case "ATTEST-EXTEND":
		ctlAttestExtend(reply, cgPath)
	case "ATTEST-QUOTE":
		ctlAttestQuote(reply, cgPath, f)
	case "ATTEST-EK":
		ctlAttestEK(reply, cgPath)
	case "ATTEST-ACTIVATE":
		ctlAttestActivate(reply, cgPath, f)
	case "ATTEST-GATE":
		ctlAttestGate(reply, cgPath)
	case "ATTEST-SELFCHECK":
		ctlAttestSelfCheck(reply, cgPath)
	default:
		reply("ERR protocol")
	}
}

// peerUID reads the connecting peer's uid from the kernel (SO_PEERCRED).
func peerUID(conn net.Conn) (uint32, bool) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *unix.Ucred
	var serr error
	if cerr := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); cerr != nil || serr != nil || cred == nil {
		return 0, false
	}
	return cred.Uid, true
}

// ---- self-verbs: write egress_policy/grant_once for the KERNEL-ATTESTED self cgid only -------

func ctlEgressSetSelf(reply func(string), cgID uint64, cgPath string, f []string) {
	if !isAgentCgroup(cgPath) {
		reply("ERR not-an-agent")
		return
	}
	if len(f) != 2 {
		reply("ERR protocol")
		return
	}
	mask, err := parseClasses(f[1])
	if err != nil {
		reply("ERR bad-classes")
		return
	}
	controlMu.Lock()
	defer controlMu.Unlock()
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "egress_policy"), nil)
	if err != nil {
		reply("ERR map")
		return
	}
	defer m.Close()
	if err := m.Update(cgID, mask, ebpf.UpdateAny); err != nil {
		recordControl("control:egress-set", "", "err", "update-failed", cgID)
		reply("ERR update")
		return
	}
	recordControl("control:egress-set", "", "ok", classNames(mask), cgID)
	reply("OK " + classNames(mask))
}

func ctlEgressClearSelf(reply func(string), cgID uint64, cgPath string) {
	if !isAgentCgroup(cgPath) {
		reply("ERR not-an-agent")
		return
	}
	controlMu.Lock()
	defer controlMu.Unlock()
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "egress_policy"), nil)
	if err != nil {
		reply("ERR map")
		return
	}
	defer m.Close()
	if err := m.Delete(cgID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		recordControl("control:egress-clear", "", "err", "delete-failed", cgID)
		reply("ERR delete")
		return
	}
	recordControl("control:egress-clear", "", "ok", "cleared", cgID)
	reply("OK cleared")
}

func ctlGrantClearSelf(reply func(string), cgID uint64, cgPath string) {
	if !isAgentCgroup(cgPath) {
		reply("ERR not-an-agent")
		return
	}
	controlMu.Lock()
	defer controlMu.Unlock()
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "grant_once"), nil)
	if err != nil {
		reply("ERR map")
		return
	}
	defer m.Close()
	for _, h := range []uint32{hookPtrace, hookSetuid, hookCapset} {
		_ = m.Delete(bpfGrantKey{Cgid: cgID, Hook: h})
	}
	recordControl("control:grant-clear", "", "ok", "cleared", cgID)
	reply("OK cleared")
}

// ---- broker TCB establishment: NEVER a caller-named cgroup ------------------------------------

// ctlTcbRegisterBroker registers the broker into tcb_cgroups. ANTI-ARBITRARY-REGISTER: it takes
// no target; the caller's attested cgroup must be string-EQUAL (filepath.Clean, not prefix/
// substring/traversal) to the fixed broker unit cgroup, and the cgid registered is the one the
// collector itself stats from brokerCgroupPath — never anything the caller supplies.
func ctlTcbRegisterBroker(reply func(string), cgPath string) {
	if !isBrokerCaller(cgPath) {
		reply("ERR not-broker")
		return
	}
	bid, err := cgroupIDFromInode(brokerCgroupPath)
	if err != nil {
		reply("ERR broker-cgroup")
		return
	}
	controlMu.Lock()
	defer controlMu.Unlock()
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "tcb_cgroups"), nil)
	if err != nil {
		reply("ERR map")
		return
	}
	defer m.Close()
	if err := m.Update(bid, uint32(1), ebpf.UpdateAny); err != nil {
		recordControl("control:tcb-register-broker", "broker", "err", "update-failed", bid)
		reply("ERR update")
		return
	}
	recordControl("control:tcb-register-broker", "broker", "ok", "registered", bid)
	reply("OK registered")
}

// ctlWaitBrokerTCB replies OK iff the broker cgid is currently in tcb_cgroups — the gate the
// enforce-arming unit polls so E0 never arms ahead of broker-TCB establishment.
func ctlWaitBrokerTCB(reply func(string)) {
	bid, err := cgroupIDFromInode(brokerCgroupPath)
	if err != nil {
		reply("ERR broker-cgroup")
		return
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "tcb_cgroups"), nil)
	if err != nil {
		reply("ERR map")
		return
	}
	defer m.Close()
	var v uint32
	if err := m.Lookup(bid, &v); err != nil {
		reply("ERR not-registered")
		return
	}
	reply("OK registered")
}

// ctlEnforceSet arms/disarms a per-hook enforce toggle FROM THE COLLECTOR'S TCB CONTEXT (ADR-0016
// review fix). The enforce_flags Update is itself a bpf() — done directly by `enforce on|off` it
// runs in the caller's cgroup, so once E0 is armed a DISARM from a non-TCB cgroup (the documented
// `systemctl stop bulkhead-enforce` kill-switch, run in the enforce unit's own non-TCB cgroup) is
// EPERM'd: the soft-disarm silently fails while systemd reports the unit stopped. Routing it here
// lets the collector (TCB, E0-exempt) do the write, so arm AND disarm work under E0. Operator-only:
// uid==0 is already required by handleControlConn, and we additionally reject AGENT cgroups so a
// jailed lineage can never flip the master switch (an agent's +ExecStartPre runs as uid-0 but in an
// agent cgroup). The authority is no broader than today's root (root can already disarm via a
// collector restart, which RemoveAll-resets enforce to observe).
func ctlEnforceSet(reply func(string), cgPath string, f []string) {
	if isAgentCgroup(cgPath) {
		reply("ERR not-operator") // an agent may never toggle the enforce master switch
		return
	}
	if len(f) != 3 || (f[2] != "0" && f[2] != "1") {
		reply("ERR protocol")
		return
	}
	hid, ok := hookID(f[1])
	if !ok {
		reply("ERR bad-hook")
		return
	}
	var val uint32
	if f[2] == "1" {
		val = 1
	}
	controlMu.Lock()
	defer controlMu.Unlock()
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "enforce_flags"), nil)
	if err != nil {
		reply("ERR map")
		return
	}
	defer m.Close()
	if err := m.Update(hid, val, ebpf.UpdateAny); err != nil {
		recordControl("control:enforce-set", f[1], "err", "update-failed", 0)
		reply("ERR update")
		return
	}
	recordControl("control:enforce-set", f[1], "ok", f[1]+"="+f[2], 0)
	reply("OK " + f[1] + "=" + f[2])
}

// ---- ctl client (run by the agent +ExecStartPre / the broker / the enforce-arm gate) ----------

func cmdControl(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector ctl egress-set-self <classes>|egress-clear-self|grant-clear-self|tcb-register-broker|wait-broker-tcb")
		os.Exit(2)
	}
	var line string
	switch args[0] {
	case "egress-set-self":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: bulkhead-collector ctl egress-set-self <classes>")
			os.Exit(2)
		}
		line = "EGRESS-SET-SELF " + args[1]
	case "egress-clear-self":
		line = "EGRESS-CLEAR-SELF"
	case "grant-clear-self":
		line = "GRANT-CLEAR-SELF"
	case "tcb-register-broker":
		line = "TCB-REGISTER-BROKER"
	case "wait-broker-tcb":
		line = "WAIT-BROKER-TCB"
	default:
		fmt.Fprintln(os.Stderr, "unknown ctl verb")
		os.Exit(2)
	}
	// wait-broker-tcb polls (the broker may still be starting); the others are one-shot. The
	// agent +ExecStartPre uses egress-set-self: a non-OK reply => non-zero exit => the unit
	// fails => the payload never forks (ADR-0005 fail-closed preserved).
	deadline := time.Now().Add(30 * time.Second)
	for {
		ok, resp := controlRPC(line)
		if ok {
			fmt.Println(resp)
			return
		}
		if args[0] != "wait-broker-tcb" || time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, resp)
			os.Exit(1)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// controlRPCRetry re-dials the control socket until OK or a bounded deadline. ADR-0018: boot-time
// callers (the broker's TCB self-registration, and the routed `enforce on` that arms E0/E2 at boot)
// can WIN a foot-race against the collector, which is Type=exec (active at execve) and binds
// /run/bulkhead/control.sock only as its LAST startup step. A single dial loses that race
// (immediate ENOENT) and would fatally fail the caller, silently leaving the box UNARMED (E2 in
// observe / the broker non-TCB). The manual/operator path succeeds on the first dial (the collector
// is long up), so the retry is transparent there.
func controlRPCRetry(line string) (bool, string) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		ok, resp := controlRPC(line)
		if ok {
			return true, resp
		}
		if time.Now().After(deadline) {
			return false, resp
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// controlRPCGate is for the posture GATE (ADR-0021): like controlRPCRetry it tolerates the boot race
// (the collector binds the socket as its LAST startup step), but it retries ONLY on a TRANSPORT
// failure (a "control dial/send/read" prefix) — a SERVER reply ("ERR not-armed ...") is returned
// IMMEDIATELY, so a legitimately-disarmed box fail-closes FAST instead of hanging the 30s boot-race
// window before reporting not-armed.
func controlRPCGate(line string) (bool, string) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		ok, resp := controlRPC(line)
		if ok {
			return true, resp
		}
		if !strings.HasPrefix(resp, "control ") { // a server reply (ERR ...), not a transport failure
			return false, resp
		}
		if time.Now().After(deadline) {
			return false, resp
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func controlRPC(line string) (bool, string) {
	conn, err := net.DialTimeout("unix", controlSockPath, 5*time.Second)
	if err != nil {
		return false, "control dial: " + err.Error()
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := fmt.Fprintln(conn, line); err != nil {
		return false, "control send: " + err.Error()
	}
	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return false, "control read: " + err.Error()
	}
	resp = strings.TrimSpace(resp)
	return strings.HasPrefix(resp, "OK"), resp
}
