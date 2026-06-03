// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

// Inter-agent egress delegation broker (ADR-0006). A parent agent (jailed, non-root,
// no caps, cannot bpf()) asks this TCB broker to spawn a child whose egress manifest is
// child = parent ∩ requested — NARROW-NEVER-WIDEN. The broker is the only thing that
// reads the live egress_policy map and launches a jail; the parent is untrusted and
// supplies ONLY a cosmetic child-suffix and a requested class set. Every identity input
// (which cgroup is asking, hence its ceiling) is attested by the kernel via SO_PEERPIDFD,
// never by anything the parent sends.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	brokerSockPath  = "/run/bulkhead/broker.sock"  // 0666, agents connect (delegation)
	approveSockPath = "/run/bulkhead/approve.sock" // 0600 root, the operator (approval)
	maxPending      = 64                           // total in-flight approvals (flood cap)
	maxPendingPar   = 4                            // per-parent-cgroup in-flight (flood cap)
)

// approvalTimeout: how long the broker blocks for an operator decision before denying.
// Default 120s; the demo overrides via BULKHEAD_APPROVAL_TIMEOUT (seconds).
var approvalTimeout = func() time.Duration {
	if v := os.Getenv("BULKHEAD_APPROVAL_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 120 * time.Second
}()

// maxDelegateDepth caps delegation RECURSION height (a child can itself delegate — the tool
// is in every agent). The depth is derived ONLY from the kernel-attested parent instance name
// (delegGen), NEVER from anything the agent sends, so a child cannot reset its own counter. A
// top-level parent is gen 0, so the default 3 permits worker -> d1 -> d2 -> d3. Fail-closed.
var maxDelegateDepth = func() int {
	if v := os.Getenv("BULKHEAD_MAX_DELEGATE_DEPTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 3
}()

// childRouterURL is the inference endpoint written into a delegated child's drop-in. It is
// read from the BROKER's OWN environment (never parent-supplied — closing SSRF-via-inference)
// and written ONLY if set; otherwise the child inherits the template default. The qemu harness
// points it at the bundled mock; production leaves it unset.
var childRouterURL = os.Getenv("BULKHEAD_CHILD_ROUTER_URL")

// actionKind names a gated sensitive action. The approval gate (register/approve/resolve/
// handleApprove/the signed chain) is action-agnostic; each kind supplies its own executor.
type actionKind string

const (
	actDelegate     actionKind = "delegate"      // spawn a child with parent ∩ requested (ADR-0006)
	actExpandEgress actionKind = "expand-egress" // widen the requester's OWN manifest (ADR-0009)
	actNarrowEgress actionKind = "narrow-egress" // operator clamps an agent's manifest (ADR-0010)
	actGrantOnce    actionKind = "grant-once"    // one-shot E1/E3 privilege grant (ADR-0011)
)

// expandCeiling is the hard per-deployment cap an EXPAND can never exceed, even with
// operator approval (defense-in-depth). Default = all DST_* classes (the operator is sole
// authority out of the box); set BULKHEAD_EXPAND_CEILING to clamp. Fail-closed on a bad value.
var expandCeiling = func() uint32 {
	v := os.Getenv("BULKHEAD_EXPAND_CEILING")
	if v == "" {
		return dstLoopback | dstLinklocal | dstPrivate | dstPublic | dstOther
	}
	m, err := parseClasses(v)
	if err != nil {
		log.Fatalf("broker: bad BULKHEAD_EXPAND_CEILING %q: %v", v, err)
	}
	return m
}()

// expandMask computes the widened manifest: keep everything current, add the requested
// classes that fall within the ceiling. A bare OR after an AND-with-ceiling — it can only
// ADD bits already permitted by the ceiling, never grant beyond it.
func expandMask(cur, req, ceiling uint32) uint32 { return cur | (req & ceiling) }

// pending is one in-flight sensitive action awaiting an operator decision.
type pending struct {
	id         uint64
	kind       actionKind // which sensitive action
	parentCgID uint64     // kernel-attested REQUESTER cgroup (parent for delegate, self for expand); flood key
	parentPath string
	suffix     string // delegate only
	instance   string // delegate only: broker-minted child unit instance (bound into the audit record)
	task       string // delegate only: the (sanitized) parent-supplied child task; "" => broker default
	gen        int    // delegate only: child generation (parent gen + 1), from the attested parent name
	reqMask    uint32 // requested classes (delegate/expand)
	childMask  uint32 // delegate: resolved child mask (parent & requested)
	curMask    uint32 // expand: requester's current manifest (for LIST/audit)
	grantHook  uint32 // grant-once: the HOOK_* id being one-shot-granted
	created    time.Time
	decision   chan bool                      // buffered cap-1; resolve() sends exactly once, never blocks
	verdict    string                         // "approve"|"deny"|"timeout"; set under pendMu before the send
	operator   string                         // operator identity; set under pendMu before the send
	execute    func(*pending) (string, error) // per-action executor; runs ONLY after approval (ok==true)
}

var (
	pendMu     sync.Mutex
	pendNext   uint64
	pend       = map[uint64]*pending{}
	pendPerPar = map[uint64]int{}
	launchMu   sync.Mutex // serialize launchChild's daemon-reload/start (one PID-1 op at a time)
	// egressMu serializes ALL broker read-modify-writes on egress_policy (operator NARROW +
	// agent EXPAND) so a narrow racing an approved expand on the SAME cgroup composes from the
	// LIVE mask with no lost update. Distinct from launchMu so it never blocks behind
	// launchChild's slow daemon-reload/systemctl section, and narrow never touches pendMu.
	egressMu sync.Mutex
	// grantMu serializes broker writes to the grant_once map (ADR-0011); distinct from
	// egressMu (different map) and launchMu (no launchChild coupling).
	grantMu  sync.Mutex
	brokerAL *auditLog // broker-owned signed decision chain (separate from the collector's)
)

// ---- broker (TCB listener) -------------------------------------------------

func cmdBroker() {
	// ADR-0016: the broker no longer self-bpf()s into tcb_cgroups — that Update from its own
	// not-yet-TCB cgroup is EPERM'd the moment E0 (lsm/bpf deny) is armed, which is exactly why
	// the full E0-E3 stack was previously un-armable alongside delegation. Instead the broker
	// ASKS the already-TCB, E0-exempt collector to register it, over the control socket, where
	// the collector kernel-attests the caller IS the broker cgroup and registers the cgid it
	// stats itself. BLOCK until OK before listening — never serve a gated action while non-TCB.
	if !brokerRegisterTCB() {
		log.Fatalf("broker: TCB registration via collector control socket failed (is the collector running?)")
	}
	// The broker owns its OWN signed decision chain (separate dir/key, via
	// BULKHEAD_AUDIT_DIR) — never the collector's single-writer provenance chain.
	al, err := openAuditLog("broker", "provenance.jsonl")
	if err != nil {
		log.Fatalf("broker: decision log: %v", err)
	}
	brokerAL = al
	log.Printf("broker: decision log at %s, signer %s", al.path, al.pubHex())

	delegLn, err := brokerListener()
	if err != nil {
		log.Fatalf("broker: delegation listen: %v", err)
	}
	approveLn, err := approveListener()
	if err != nil {
		log.Fatalf("broker: approve listen: %v", err)
	}
	log.Printf("broker: armed (delegation: child = parent ∩ requested; approval-gate timeout %s)", approvalTimeout)

	// Two INDEPENDENT accept loops + goroutine-per-conn: a delegation blocked in the
	// approval gate must NOT wedge the broker from accepting the operator's decision
	// (the serialized inline-handle loop would self-deadlock).
	go acceptLoop(approveLn, handleApprove)
	acceptLoop(delegLn, handleBrokerConn)
}

func acceptLoop(ln net.Listener, h func(net.Conn)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("broker: accept: %v", err)
			continue
		}
		go h(conn)
	}
}

// approveListener creates the operator control socket: root-only (0600) so a non-root
// agent (DynamicUser) gets EACCES at connect(); handleApprove additionally checks the
// peer uid via SO_PEERCRED. The broker creates it in-process (no extra .socket unit).
func approveListener() (net.Listener, error) {
	_ = os.Remove(approveSockPath)
	ln, err := net.Listen("unix", approveSockPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(approveSockPath, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// brokerListener prefers systemd socket activation (LISTEN_FDS fd 3); else binds the path.
func brokerListener() (net.Listener, error) {
	if os.Getenv("LISTEN_PID") == strconv.Itoa(os.Getpid()) && os.Getenv("LISTEN_FDS") != "" {
		f := os.NewFile(3, "bulkhead-broker.sock") // SD_LISTEN_FDS_START
		defer f.Close()
		return net.FileListener(f)
	}
	_ = os.Remove(brokerSockPath)
	if err := os.MkdirAll(filepath.Dir(brokerSockPath), 0o755); err != nil {
		return nil, err
	}
	return net.Listen("unix", brokerSockPath)
}

// brokerRegisterTCB asks the collector (over the control socket) to add THIS broker's cgroup to
// tcb_cgroups. The broker issues no bpf() itself; the collector attests the caller is the broker
// cgroup and registers the cgid it stats from the fixed path. Returns true only on OK.
func brokerRegisterTCB() bool {
	ok, resp := controlRPC("TCB-REGISTER-BROKER")
	if !ok {
		log.Printf("broker: TCB-REGISTER-BROKER: %s", resp)
	}
	return ok
}

// handleBrokerConn serves one agent request on the delegation socket. It peer-attests the
// requester from the kernel, reads one verb line, and dispatches: DELEGATE (spawn a
// narrowed child, ADR-0006) or EXPAND (widen the requester's OWN manifest, ADR-0009). Both
// flow through the same approval gate (finishGated); only the executor differs.
func handleBrokerConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second)) // a slow/hostile peer can't wedge the loop
	reply := func(s string) { fmt.Fprintln(conn, s) }

	// Kernel-attested requester identity (NEVER from the request body).
	cgID, cgPath, err := peerParentCgID(conn)
	if err != nil {
		log.Printf("broker: peer-auth: %v", err)
		reply("ERR peer-auth")
		return
	}
	// Only a real jailed agent may use the broker (a TCB process must not). Structural match
	// (ADR-0016 review): an anchored agent-instance leaf, so a crafted uid-0 cgroup path that
	// merely embeds the marker (a nested sub-scope, or a marker-named slice elsewhere) is rejected.
	if !isAgentCgroup(cgPath) {
		log.Printf("broker: reject non-agent cgroup %q", cgPath)
		reply("ERR not-an-agent")
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
	case "DELEGATE":
		handleDelegateTail(conn, cgID, cgPath, f)
	case "EXPAND":
		handleExpandTail(conn, cgID, cgPath, f)
	case "GRANT-ONCE":
		handleGrantOnceTail(conn, cgID, cgPath, f)
	default:
		reply("ERR protocol")
	}
}

// handleDelegateTail: DELEGATE <child-suffix> <requested-classes> [task...] — spawn a child
// whose manifest is parent ∩ requested (NARROW-never-widen, ADR-0006) running the real agent
// runtime on a parent-supplied task (ADR-0015). The task is sanitized here (fail-closed before
// any side effect) and delivered to the child as a systemd CREDENTIAL (file content), NEVER as
// unit syntax — so a "\nExecStartPre=…" payload cannot inject a directive.
func handleDelegateTail(conn net.Conn, parentCgID uint64, parentPath string, f []string) {
	reply := func(s string) { fmt.Fprintln(conn, s) }
	suffix, reqStr, task, ok := parseDelegateTail(f)
	if !ok {
		reply("ERR protocol")
		return
	}
	if !validSuffix(suffix) {
		reply("ERR bad-suffix")
		return
	}
	reqMask, err := parseClasses(reqStr)
	if err != nil {
		reply("ERR bad-classes")
		return
	}
	// Sanitize the parent-supplied task BEFORE registering or any side effect: a hostile task
	// (control chars / over-length) spawns no child, no cgroup, no .task file. Empty is allowed
	// (=> broker default task). This is defense-in-depth layered atop the non-unit channel.
	if err := validTask(task); err != nil {
		reply("ERR bad-task")
		return
	}
	// Depth cap from the kernel-attested parent generation (never agent-supplied). A child at
	// the max depth may not spawn a grandchild — bounds recursion height. Checked BEFORE the
	// map read so a too-deep request never touches kernel state.
	gen, err := delegGen(parentPath)
	if err != nil {
		reply("ERR bad-parent")
		return
	}
	if gen+1 > maxDelegateDepth {
		reply("ERR too-deep")
		return
	}
	// Parent's CURRENT ceiling from the live pinned map. Miss => cannot delegate (you
	// cannot safely subset "unrestricted"). Fail-closed.
	parentMask, err := lookupEgressMask(parentCgID)
	if err != nil {
		reply("ERR no-parent-manifest")
		return
	}
	childMask := parentMask & reqMask // request-time view; ADVISORY (re-derived in execute)
	p := &pending{
		kind: actDelegate, parentCgID: parentCgID, parentPath: parentPath, suffix: suffix,
		instance: "d" + strconv.Itoa(gen+1) + "-" + randHex8() + "-" + suffix,
		reqMask:  reqMask, childMask: childMask, task: task, gen: gen + 1,
		created: time.Now(),
	}
	// The child's own +ExecStartPre writes its (narrowed) manifest before its payload forks.
	p.execute = func(p *pending) (string, error) {
		launchMu.Lock()
		defer launchMu.Unlock()
		// F3: re-derive from LIVE parent state after the gate. If the parent exited and its
		// cgroup recycled, or it NARROWED its own manifest during the approval gap, the
		// request-time childMask is stale and could over-grant. Re-stat the parent's identity
		// and re-read its live mask; recompute child = liveParent ∩ requested. Fail closed.
		//
		// F6 (composed review): take egressMu around the parent-mask READ so an operator
		// NARROW/EXPAND (which serialize on egressMu) cannot interleave BETWEEN this read and
		// the slow launchChild — otherwise a `narrow P public` meant to contain an incident
		// could land after the read and the child would be born holding the class the operator
		// just revoked. Snapshot the child mask under egressMu; launch OUTSIDE it. Lock order
		// is launchMu->egressMu held briefly; expand/narrow take egressMu alone, so no inversion.
		egressMu.Lock()
		err := reverifyCgroup(p.parentPath, p.parentCgID)
		var liveChild uint32
		if err == nil {
			var liveParent uint32
			liveParent, err = lookupEgressMask(p.parentCgID)
			liveChild = liveParent & p.reqMask
		}
		egressMu.Unlock()
		if err != nil {
			return "", fmt.Errorf("parent re-verify/manifest: %w", err)
		}
		if err := launchChild(p.instance, classNames(liveChild), p.task); err != nil {
			return "", err
		}
		return p.instance + " " + classNames(liveChild), nil
	}
	_ = conn.SetDeadline(time.Now().Add(approvalTimeout + 15*time.Second))
	finishGated(conn, p)
}

// handleExpandTail: EXPAND <classes> — the requester asks to WIDEN ITS OWN manifest. The
// target is the kernel-attested SELF (agentCgID); the request body carries no identity, so
// an agent can only ever widen itself, never another. The map write happens in execute() —
// ONLY after operator approval — re-reading the LIVE mask and using UpdateExist, so a
// request that outlived its agent (cgroup exited/recycled) can never resurrect a manifest.
func handleExpandTail(conn net.Conn, agentCgID uint64, agentPath string, f []string) {
	reply := func(s string) { fmt.Fprintln(conn, s) }
	if len(f) != 2 {
		reply("ERR protocol")
		return
	}
	reqMask, err := parseClasses(f[1])
	if err != nil {
		reply("ERR bad-classes")
		return
	}
	curMask, err := lookupEgressMask(agentCgID)
	if err != nil {
		// Unrestricted (no manifest): nothing to widen, and CREATING one would NARROW the
		// agent (every unset class becomes a deny once E2 bites). Refuse.
		reply("ERR no-manifest")
		return
	}
	newMask := expandMask(curMask, reqMask, expandCeiling)
	if newMask == curMask { // no new grantable bit — don't burn an operator decision
		if reqMask&^curMask != 0 {
			reply("ERR above-ceiling") // asked for new classes, all clamped by the ceiling
		} else {
			reply("OK " + classNames(curMask) + " (no-op)") // already holds everything requested
		}
		return
	}
	cgID := agentCgID // capture the ATTESTED id for the closure — never peer-supplied
	p := &pending{
		kind: actExpandEgress, parentCgID: agentCgID, parentPath: agentPath,
		reqMask: reqMask, curMask: curMask, created: time.Now(),
	}
	p.execute = func(p *pending) (string, error) {
		// Serialize against operator NARROW (ADR-0010): both read-modify-write egress_policy,
		// so without a shared lock a concurrent narrow could lose this widen (or vice versa).
		// Each holder re-reads the LIVE mask under egressMu, so the result composes by
		// lock-acquisition order. (launchChild is never called here, so no lock-order issue.)
		egressMu.Lock()
		defer egressMu.Unlock()
		// F1: re-bind identity to the LIVE cgroup before touching its manifest. UpdateExist
		// is necessary but NOT sufficient — if cgID was recycled onto a new agent that wrote
		// its own manifest, UpdateExist succeeds and we widen the WRONG agent. Re-stat first.
		if err := reverifyCgroup(p.parentPath, cgID); err != nil {
			return "", err
		}
		m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "egress_policy"), nil)
		if err != nil {
			return "", err
		}
		defer m.Close()
		var live uint32
		if err := m.Lookup(cgID, &live); err != nil {
			return "", fmt.Errorf("manifest vanished") // agent exited/cleared -> refuse
		}
		final := expandMask(live, p.reqMask, expandCeiling) // recompute from LIVE; never past the ceiling
		if err := m.Update(cgID, final, ebpf.UpdateExist); err != nil {
			return "", err // UpdateExist: never CREATE on a stale/recycled cgroup
		}
		return classNames(final), nil
	}
	_ = conn.SetDeadline(time.Now().Add(approvalTimeout + 15*time.Second))
	finishGated(conn, p)
}

// finishGated runs the single blocking approval gate, then (only on approve) the action's
// executor, then replies. The ONLY place execute() is ever called — deny/timeout/flood
// reply ERR and never reach a side effect.
func finishGated(conn net.Conn, p *pending) {
	reply := func(s string) { fmt.Fprintln(conn, s) }
	ok, verdict := approve(p)
	if !ok {
		// deny | timeout | busy — no side effect ran; record the (non-)decision.
		if err := recordDecision(p, verdict, p.operator, "(not applied)"); err != nil {
			log.Printf("broker: AUDIT APPEND FAILED for %s %s: %v", p.kind, verdict, err)
		}
		reply("ERR " + verdict)
		return
	}
	// execute() re-derives the live kernel/map state under the attested identity and
	// fails closed on any mismatch (cgroup recycle, parent narrowed) — request-time
	// captures are advisory only. The signed record below is written AFTER the side
	// effect and reflects what was ACTUALLY applied, so the audit can neither claim a
	// widen that did not land nor miss one that did.
	detail, err := p.execute(p)
	if err != nil {
		log.Printf("broker: execute %s id=%d: %v", p.kind, p.id, err)
		if rerr := recordDecision(p, "error", p.operator, "(execute failed: "+err.Error()+")"); rerr != nil {
			log.Printf("broker: AUDIT APPEND FAILED for %s error: %v", p.kind, rerr)
		}
		reply("ERR exec")
		return
	}
	// F7 (composed review): the side effect landed; the signed record is now load-bearing,
	// not advisory. If the append FAILS, do NOT reply OK — the action is unrecorded, so
	// surface it (ERR audit) and log loudly rather than silently claiming success.
	if rerr := recordDecision(p, verdict, p.operator, detail); rerr != nil {
		log.Printf("broker: AUDIT APPEND FAILED after applied %s cg=%d -> %s: %v", p.kind, p.parentCgID, detail, rerr)
		reply("ERR audit")
		return
	}
	log.Printf("broker: %s cg=%d -> %s [operator %s]", p.kind, p.parentCgID, detail, p.operator)
	reply("OK " + detail)
}

// peerParentCgID attests the connecting agent's cgroup id from the kernel. SO_PEERPIDFD
// captures, at connect() time, a pidfd bound to the connecting task's struct pid — which
// pins the pid NUMBER against recycle while we hold it, closing the connect→read TOCTOU.
// We read the authoritative pid from the pidfd's fdinfo, then that pid's cgroup.
func peerParentCgID(conn net.Conn) (uint64, string, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, "", fmt.Errorf("not a unix conn")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, "", err
	}
	var pidfd int
	var sockErr error
	if cerr := raw.Control(func(fd uintptr) {
		pidfd, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	}); cerr != nil {
		return 0, "", cerr
	}
	if sockErr != nil {
		return 0, "", fmt.Errorf("SO_PEERPIDFD: %w", sockErr)
	}
	defer unix.Close(pidfd)

	pid, err := pidFromPidfd(pidfd)
	if err != nil {
		return 0, "", err
	}
	// The pidfd pins the connecting task's struct pid, which RESERVES the pid number
	// against recycle for as long as we hold the fd. So /proc/<pid>/cgroup is provably
	// the original parent's: it is either that task (alive or zombie) or absent (if
	// reaped) — never a different process. A reaped parent => ReadFile fails => we
	// fail closed below. (No signal-based liveness recheck: it would need CAP_KILL to
	// signal the parent's DynamicUser uid, and the pin already makes it redundant.)
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return 0, "", fmt.Errorf("read peer cgroup: %w", err)
	}
	path := cgroupPathFromBytes(data)
	if path == "" {
		return 0, "", fmt.Errorf("no v2 cgroup line for peer")
	}
	cg, err := cgroupIDFromInode(filepath.Join("/sys/fs/cgroup", path))
	if err != nil {
		return 0, "", err
	}
	return cg, path, nil
}

func pidFromPidfd(pidfd int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", pidfd))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Pid:") {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				return strconv.Atoi(fields[1])
			}
		}
	}
	return 0, fmt.Errorf("no Pid in pidfd fdinfo")
}

func cgroupPathFromBytes(data []byte) string {
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, "0::") { // v2 unified hierarchy
			return strings.TrimPrefix(line, "0::")
		}
	}
	return ""
}

// reverifyCgroup re-binds the requester's identity at execute() time. SO_PEERPIDFD attested
// (want, path) at REQUEST time, but the operator gate opens a human-paced gap during which
// the agent can exit and its cgroup inode can be RECYCLED onto a different live agent at the
// same path (a restart) or the path can vanish. We re-stat the path and demand the live
// cgroup id still equals the attested one — request-time captures are advisory; only this
// live re-derivation may be trusted to drive a side effect. Fail-closed: a vanished path or
// any id mismatch returns an error and execute() applies NOTHING. This is the single rule
// that closes the F1 (expand widens wrong agent) / F3 (delegate off a recycled parent)
// inode-identity cluster; ebpf.UpdateExist alone does NOT (it refuses only to CREATE a
// missing key — it happily writes a recycled key that a new agent's ExecStartPre populated).
func reverifyCgroup(path string, want uint64) error {
	live, err := cgroupIDFromInode(filepath.Join("/sys/fs/cgroup", path))
	if err != nil {
		return fmt.Errorf("requester cgroup gone (%s): %w", path, err)
	}
	if live != want {
		return fmt.Errorf("requester cgroup recycled (%s: live=%d attested=%d)", path, live, want)
	}
	return nil
}

func lookupEgressMask(cgID uint64) (uint32, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "egress_policy"), nil)
	if err != nil {
		return 0, err
	}
	defer m.Close()
	var mask uint32
	if err := m.Lookup(cgID, &mask); err != nil {
		return 0, err // miss => parent has no manifest => may not delegate
	}
	return mask, nil
}

// parseDelegateTail extracts (suffix, classes, task) from a tokenized DELEGATE line
// f = ["DELEGATE", suffix, classes, task-word...]. The task is f[3:] re-joined with single
// spaces (empty if absent — the broker-default path). ok=false if there are too few fields.
// PURE (no I/O) so the wire parsing is unit-testable without a kernel or socket.
func parseDelegateTail(f []string) (suffix, classes, task string, ok bool) {
	if len(f) < 3 {
		return "", "", "", false
	}
	if len(f) > 3 {
		task = strings.Join(f[3:], " ")
	}
	return f[1], f[2], task, true
}

// validTask gates a parent-supplied child task. The task reaches the child via a systemd
// CREDENTIAL (file content), NEVER as unit/Environment= syntax, so this is defense-in-depth,
// not the primary barrier: reject any byte that could matter to a parser or break out of a
// single transcript line (NUL, newline, CR, tab, any control or non-ASCII byte) and cap the
// length. Empty is allowed (means "broker default task"). Called fail-closed BEFORE any side
// effect, so a hostile task creates no child, no cgroup, no .task file.
func validTask(s string) error {
	if s == "" {
		return nil
	}
	if len(s) > 4096 {
		return fmt.Errorf("task too long (%d > 4096)", len(s))
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e { // printable ASCII only
			return fmt.Errorf("task has a non-printable-ASCII byte at offset %d", i)
		}
	}
	return nil
}

// delegGen derives a delegation generation from the kernel-attested parent instance name in
// its cgroup path: a top-level parent (worker/agentA/…) is gen 0; a broker-minted child
// "d<N>-<hex>-<suffix>" is gen N. Depth is therefore rooted in attested identity, never in
// anything the agent supplies, so a child cannot reset its own counter. A path with no agent
// instance fails closed.
func delegGen(parentPath string) (int, error) {
	const marker = "bulkhead-agent@"
	i := strings.LastIndex(parentPath, marker)
	if i < 0 {
		return 0, fmt.Errorf("no agent instance in %q", parentPath)
	}
	inst := parentPath[i+len(marker):]
	if j := strings.Index(inst, ".service"); j >= 0 {
		inst = inst[:j]
	}
	if inst == "" {
		return 0, fmt.Errorf("empty instance in %q", parentPath)
	}
	// "d<digits>-…" => generation <digits>; ANYTHING else (a name, the legacy d-<hex> form)
	// => a top-level parent at gen 0.
	if len(inst) >= 2 && inst[0] == 'd' && inst[1] >= '0' && inst[1] <= '9' {
		k := 1
		for k < len(inst) && inst[k] >= '0' && inst[k] <= '9' {
			k++
		}
		if k < len(inst) && inst[k] == '-' {
			return strconv.Atoi(inst[1:k])
		}
	}
	return 0, nil
}

// taskSHA8 binds the EXACT task bytes into the signed record without logging the (attacker-
// influenced) text: the first 8 hex of its SHA-256, or "(default)" for the no-task path.
func taskSHA8(task string) string {
	if task == "" {
		return "(default)"
	}
	sum := sha256.Sum256([]byte(task))
	return hex.EncodeToString(sum[:])[:8]
}

// taskPreview renders a short, already-sanitized (validTask: printable ASCII) task for the
// operator's LIST so they approve with context. Empty => "(default)".
func taskPreview(task string) string {
	if task == "" {
		return "(default)"
	}
	if len(task) > 40 {
		return task[:40] + "…"
	}
	return task
}

func validSuffix(s string) bool {
	if len(s) < 1 || len(s) > 24 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func randHex8() string {
	var b [4]byte
	_, _ = rand.Read(b[:]) // crypto/rand
	return hex.EncodeToString(b[:])
}

// delegatedDropIn builds the child's transient systemd drop-in. EVERY value here is a
// broker-controlled token: classes is a classNames() enum join, instance is broker-minted,
// routerURL is the broker's OWN env. The parent-supplied TASK NEVER appears — it rides a
// LoadCredential (file content PID-1 materializes into the child's $CREDENTIALS_DIRECTORY as a
// 0400 ramfs entry owned by the child's DynamicUser uid), so a "\nExecStartPre=…" payload in
// the task is structurally inert. The function does not even TAKE the task — only whether one
// is present — so by construction it cannot leak into unit syntax (a unit test asserts this).
func delegatedDropIn(classes, instance, routerURL string, hasTask bool) string {
	var b strings.Builder
	b.WriteString("[Service]\n")
	// Broker-minted children run the REAL agent runtime: reset-then-set the template's stub
	// ExecStart (the @worker pattern) so a delegated child is a full perceive->decide->act loop.
	b.WriteString("ExecStart=\n")
	b.WriteString("ExecStart=/usr/bin/bulkhead-agent %i\n")
	b.WriteString("Environment=BULKHEAD_AGENT_EGRESS=" + classes + "\n")
	b.WriteString("Environment=BULKHEAD_AGENT_DEADLINE=120\n")
	b.WriteString("Environment=BULKHEAD_AGENT_MAX_STEPS=6\n")
	// Authority is MONOTONICALLY NON-INCREASING down a delegated lineage. Two env flags make
	// that a LIFETIME guarantee (not just spawn-time):
	//   - ALLOW_DELEGATE=1: the child may itself delegate, but only ever a NARROWER grandchild
	//     (grandchild = child & requested), bounded by the kernel-attested depth cap
	//     (delegGen/maxDelegateDepth) and the per-level uid-0 gate.
	//   - NO_EXPAND=1: the child may NOT widen its OWN egress via request_egress/EXPAND. Without
	//     this a delegated child — which runs the real runtime, so request_egress is in its tool
	//     set — could, with a fresh operator approval, climb past its parent up to the deployment
	//     expandCeiling (ADR-0009 makes EXPAND parent-unbounded). Disabling self-EXPAND keeps the
	//     subtree hard-capped by its delegation root's mask, so grandchild ⊆ child ⊆ parent holds
	//     for their lifetimes. Escalation is pushed UP to operator-launched (root) agents.
	b.WriteString("Environment=BULKHEAD_AGENT_ALLOW_DELEGATE=1\n")
	b.WriteString("Environment=BULKHEAD_AGENT_NO_EXPAND=1\n")
	if hasTask {
		// The task is delivered as a credential (file CONTENT), not Environment=/a directive.
		b.WriteString("LoadCredential=agent-task:/run/bulkhead/tasks/" + instance + ".task\n")
		b.WriteString("Environment=BULKHEAD_AGENT_TASK_CRED=agent-task\n")
	} else {
		// No parent task => a benign broker-CONSTANT default so the child still has work. The
		// value has spaces, so the WHOLE assignment is double-quoted (systemd would otherwise
		// split it into invalid assignments).
		b.WriteString("Environment=\"BULKHEAD_AGENT_TASK=Report your egress manifest over loopback, then finish.\"\n")
	}
	if routerURL != "" {
		b.WriteString("Environment=BULKHEAD_ROUTER_URL=" + routerURL + "\n")
	}
	return b.String()
}

// launchChild writes the (optional) task to a broker-owned credential-source file, then a
// transient /run drop-in carrying the narrowed manifest + the real-agent ExecStart, then starts
// the jail instance. systemctl start blocks until the unit's +ExecStartPre (which writes
// egress_policy[child]) and ExecStart have run, so the broker only replies OK once the child's
// manifest is in the map — the child payload cannot connect() before that. Fail-closed: any
// write error means NO child launches.
func launchChild(instance, classes, task string) error {
	unit := "bulkhead-agent@" + instance + ".service"
	// Write the task to a broker-owned source file BEFORE the drop-in, so the credential exists
	// when PID-1 materializes it at start. 0640 root:root under /run/bulkhead (broker's RW hole);
	// PID-1 reads it and copies it 0400 into the child's $CREDENTIALS_DIRECTORY (uid-scoped, torn
	// down with the unit). The attacker-controlled bytes are only ever file CONTENT here.
	if task != "" {
		// 0700: the broker is the only userspace reader/writer (PID-1 reads the source as root
		// for LoadCredential). A non-root child must not be able to readdir this and enumerate
		// sibling instance names (delegation topology — suffixes, generations, sibling counts).
		if err := os.MkdirAll("/run/bulkhead/tasks", 0o700); err != nil {
			return err
		}
		if err := os.WriteFile("/run/bulkhead/tasks/"+instance+".task", []byte(task), 0o640); err != nil {
			return err
		}
	}
	dropDir := filepath.Join("/run/systemd/system", unit+".d")
	if err := os.MkdirAll(dropDir, 0o755); err != nil {
		return err
	}
	conf := delegatedDropIn(classes, instance, childRouterURL, task != "")
	if err := os.WriteFile(filepath.Join(dropDir, "20-delegated-egress.conf"), []byte(conf), 0o644); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("daemon-reload: %v: %s", err, out)
	}
	if out, err := exec.Command("systemctl", "start", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("start %s: %v: %s", unit, err, out)
	}
	return nil
}

// ---- human approval-gate (ADR-0007) ----------------------------------------

// approveDelegation blocks until an operator decides or the timeout fires, then records
// the signed decision. Returns (allowed, verdict). The pending entry is removed by
// whichever of the operator-decision or the timeout fires first (delete-under-lock makes
// the verdict exactly-once); fail-closed on every non-approve path.
func approve(p *pending) (bool, string) {
	if !register(p) {
		return false, "busy" // flood; finishGated records it (no side effect ran)
	}
	timer := time.AfterFunc(approvalTimeout, func() { resolve(p.id, false, "timeout", "-") })
	ok := <-p.decision // single source of truth; verdict/operator set under lock before the send
	timer.Stop()
	// NB: recording is done by finishGated AFTER execute(), so the signed record reflects
	// the ACTUALLY-APPLIED state + the re-verified identity (not the request-time capture).
	return ok, p.verdict
}

func register(p *pending) bool {
	pendMu.Lock()
	defer pendMu.Unlock()
	if len(pend) >= maxPending || pendPerPar[p.parentCgID] >= maxPendingPar {
		return false // flood backstop -> ERR busy
	}
	pendNext++
	p.id = pendNext
	p.decision = make(chan bool, 1)
	pend[p.id] = p
	pendPerPar[p.parentCgID]++
	return true
}

// resolve delivers a verdict to a pending request exactly once. The first caller to
// delete the map entry under pendMu wins; a later operator decision OR the timeout finds
// nothing and is a clean no-op. verdict/operator are set under the lock, before the
// (buffered, non-blocking) send, so approveDelegation reads them safely after receive.
func resolve(id uint64, ok bool, verdict, operator string) bool {
	pendMu.Lock()
	p := pend[id]
	if p == nil {
		pendMu.Unlock()
		return false
	}
	delete(pend, id)
	pendPerPar[p.parentCgID]--
	p.verdict = verdict
	p.operator = operator
	pendMu.Unlock()
	p.decision <- ok
	return true
}

func listPending() string {
	pendMu.Lock()
	defer pendMu.Unlock()
	if len(pend) == 0 {
		return "(no pending requests)\n"
	}
	var b strings.Builder
	for _, p := range pend {
		age := int(time.Since(p.created).Seconds())
		switch p.kind {
		case actExpandEgress:
			// The operator reads "agent X wants to ADD <classes>": current -> proposed-new.
			fmt.Fprintf(&b, "id=%d action=expand-egress agent=%s current=%s requested=%s grant=%s age=%ds\n",
				p.id, p.parentPath, classNames(p.curMask), classNames(p.reqMask),
				classNames(expandMask(p.curMask, p.reqMask, expandCeiling)), age)
		case actGrantOnce:
			// "agent X wants ONE <hook> op": the operator authorizes a single E1/E3 exception.
			fmt.Fprintf(&b, "id=%d action=grant-once agent=%s hook=%s grant=count=1 age=%ds\n",
				p.id, p.parentPath, hookNames[p.grantHook], age)
		default: // delegate
			// The operator authorizes the (suffix, classes, depth) EDGE; the task is bound by
			// task_sha (the same artifact in the signed record). task= is a truncated preview for
			// context, NOT the full authorization basis — a long task is bound by its hash, not read.
			fmt.Fprintf(&b, "id=%d action=delegate parent=%s suffix=%s requested=%s granted=%s gen=%d task=%q task_sha=%s age=%ds\n",
				p.id, p.parentPath, p.suffix, classNames(p.reqMask), classNames(p.childMask), p.gen, taskPreview(p.task), taskSHA8(p.task), age)
		}
	}
	return b.String()
}

// handleApprove serves the operator control socket. AUTH: the peer must be uid 0
// (SO_PEERCRED) — the unforgeable operator identity. (NB: deliberately NOT a TCB-cgroup
// check: a root login/ssh lands in user.slice/session.scope, NOT a TCB cgroup, so a
// cgroup check would false-reject the legitimate operator. Agents cannot reach uid 0:
// empty caps + NoNewPrivileges + E3 setuid/capset deny, and the 0600 socket EACCESes
// their non-root DynamicUser anyway.)
func handleApprove(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		fmt.Fprintln(conn, "ERR internal")
		return
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		fmt.Fprintln(conn, "ERR internal")
		return
	}
	var cred *unix.Ucred
	var serr error
	if cerr := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); cerr != nil || serr != nil || cred == nil || cred.Uid != 0 {
		fmt.Fprintln(conn, "ERR not-operator")
		return
	}
	operator := fmt.Sprintf("uid%d:pid%d", cred.Uid, cred.Pid)

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Fprintln(conn, "ERR read")
		return
	}
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) == 0 {
		fmt.Fprintln(conn, "ERR protocol")
		return
	}
	switch f[0] {
	case "LIST":
		fmt.Fprint(conn, listPending())
	case "ALLOW", "DENY":
		if len(f) != 2 {
			fmt.Fprintln(conn, "ERR protocol")
			return
		}
		id, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			fmt.Fprintln(conn, "ERR bad-id")
			return
		}
		allow := f[0] == "ALLOW"
		v := "deny"
		if allow {
			v = "approve"
		}
		if resolve(id, allow, v, operator) {
			fmt.Fprintf(conn, "OK %s %d\n", strings.ToLower(f[0]), id)
		} else {
			fmt.Fprintln(conn, "ERR no-such-pending")
		}
	case "NARROW":
		// Operator-initiated, ungated (ADR-0010): the operator IS the authority the gate
		// consults, so a narrow runs synchronously here — no pending, no approval block.
		handleNarrow(conn, operator, f)
	default:
		fmt.Fprintln(conn, "ERR protocol")
	}
}

// recordDecision appends one signed record to the broker's OWN chain (never the
// collector's). Overloads provEvent's 6 fields: cgroup=requester, comm=child instance/self,
// hook=kind, decision=verdict, mode="<operator> req=<requested> applied=<actual>".
//
// Called exactly once per request, by finishGated AFTER execute(). `applied` is execute()'s
// returned detail — the ACTUALLY-applied grant — or "(not applied)"/"(execute failed: …)"
// when no side effect landed. The record therefore reflects what the kernel/map state truly
// became (F4), never the request-time intent, and never a widen that was refused by the
// execute()-time re-verification (F1/F3).
func recordDecision(p *pending, verdict, operator, applied string) error {
	if brokerAL == nil {
		return nil
	}
	hook := string(p.kind)
	comm := p.instance // delegate: the minted child instance
	if p.kind == actExpandEgress || p.kind == actGrantOnce {
		comm = "self"
	}
	if len(comm) > 16 {
		comm = comm[:16]
	}
	mode := fmt.Sprintf("%s req=%s applied=%s", operator, classNames(p.reqMask), applied)
	switch p.kind {
	case actGrantOnce:
		// grant-once has no class mask; render the granted hook instead of classNames(0).
		mode = fmt.Sprintf("%s op=%s applied=%s", operator, hookNames[p.grantHook], applied)
	case actDelegate:
		// Bind the child generation + the EXACT task bytes (by hash, never the text) so an
		// operator can forensically follow a parent->child->grandchild chain and tie a record
		// to the precise task that ran.
		mode = fmt.Sprintf("%s req=%s applied=%s gen=%d task_sha=%s",
			operator, classNames(p.reqMask), applied, p.gen, taskSHA8(p.task))
	}
	ev := provEvent{CgroupID: p.parentCgID, PID: 0, Comm: comm, Hook: hook, Decision: verdict, Mode: mode}
	return brokerAL.append(ev)
}

// ---- approve (operator CLI: list / allow / deny) ---------------------------

func cmdApprove(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector approve list|allow <id>|deny <id>")
		os.Exit(2)
	}
	var msg string
	switch args[0] {
	case "list":
		msg = "LIST"
	case "allow", "deny":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: bulkhead-collector approve allow|deny <id>")
			os.Exit(2)
		}
		msg = strings.ToUpper(args[0]) + " " + args[1]
	default:
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector approve list|allow <id>|deny <id>")
		os.Exit(2)
	}
	conn, err := net.DialTimeout("unix", approveSockPath, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "approve: dial: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintln(conn, msg); err != nil {
		fmt.Fprintf(os.Stderr, "approve: send: %v\n", err)
		os.Exit(1)
	}
	b, _ := io.ReadAll(conn)
	os.Stdout.Write(b)
	if bytes.Contains(b, []byte("ERR")) {
		os.Exit(1)
	}
}

// ---- delegate (client run by the parent agent INSIDE its jail) -------------

func cmdDelegate(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector delegate <child-suffix> <requested-classes> [task...]")
		os.Exit(2)
	}
	conn, err := net.DialTimeout("unix", brokerSockPath, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "delegate: dial broker: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	// The broker blocks up to its approval timeout (default 120s) for an operator
	// decision; this deadline MUST exceed it so the broker's definite verdict
	// (OK/ERR) always lands before the client gives up. Default 180s; demo lowers it.
	to := 180 * time.Second
	if v := os.Getenv("BULKHEAD_DELEGATE_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			to = time.Duration(n) * time.Second
		}
	}
	_ = conn.SetDeadline(time.Now().Add(to))
	// The task (args[2:], a single joined element from the agent tool) rides the wire line
	// verbatim; the broker re-reads the whole line and validates it. Re-join defensively in
	// case the CLI was invoked with the task as separate argv words.
	line := "DELEGATE " + args[0] + " " + args[1]
	if len(args) > 2 {
		line += " " + strings.Join(args[2:], " ")
	}
	if _, err := fmt.Fprintf(conn, "%s\n", line); err != nil {
		fmt.Fprintf(os.Stderr, "delegate: send: %v\n", err)
		os.Exit(1)
	}
	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "delegate: read reply: %v\n", err)
		os.Exit(1)
	}
	resp = strings.TrimSpace(resp)
	fmt.Println(resp)
	if !strings.HasPrefix(resp, "OK ") {
		os.Exit(1)
	}
}

// ---- expand (client run by an agent INSIDE its jail to widen its OWN egress) -----

func cmdExpand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector expand <requested-classes>")
		os.Exit(2)
	}
	conn, err := net.DialTimeout("unix", brokerSockPath, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "expand: dial broker: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	// Deadline must exceed the broker's approval timeout so its definite OK/ERR always
	// lands first. Default 180s; the demo lowers it (still > the broker timeout).
	to := 180 * time.Second
	if v := os.Getenv("BULKHEAD_EXPAND_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			to = time.Duration(n) * time.Second
		}
	}
	_ = conn.SetDeadline(time.Now().Add(to))
	if _, err := fmt.Fprintf(conn, "EXPAND %s\n", args[0]); err != nil {
		fmt.Fprintf(os.Stderr, "expand: send: %v\n", err)
		os.Exit(1)
	}
	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "expand: read reply: %v\n", err)
		os.Exit(1)
	}
	resp = strings.TrimSpace(resp)
	fmt.Println(resp)
	if !strings.HasPrefix(resp, "OK ") {
		os.Exit(1)
	}
}
