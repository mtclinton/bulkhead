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
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const controlSockPath = "/run/bulkhead/control.sock"

// agentSliceMarker: a self-verb is honored ONLY for a caller whose kernel-attested cgroup is a
// real agent jail (so an arbitrary system process cannot set/clear an egress manifest).
const agentSliceMarker = "/bulkhead-agent.slice/bulkhead-agent@"

// isAgentSelfCaller reports whether a kernel-attested cgroup PATH belongs to a bulkhead agent
// jail — the gate on every self-verb (the body never names a cgroup; the cgid is the attested
// caller's). PURE so the guard is unit-testable without a kernel.
func isAgentSelfCaller(cgPath string) bool {
	return strings.Contains(cgPath, agentSliceMarker)
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
var controlMu sync.Mutex

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
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
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
	if !isAgentSelfCaller(cgPath) {
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
		reply("ERR update")
		return
	}
	reply("OK " + classNames(mask))
}

func ctlEgressClearSelf(reply func(string), cgID uint64, cgPath string) {
	if !isAgentSelfCaller(cgPath) {
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
		reply("ERR delete")
		return
	}
	reply("OK cleared")
}

func ctlGrantClearSelf(reply func(string), cgID uint64, cgPath string) {
	if !isAgentSelfCaller(cgPath) {
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
		reply("ERR update")
		return
	}
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
