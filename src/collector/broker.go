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

// pending is one in-flight delegation awaiting an operator decision.
type pending struct {
	id         uint64
	parentCgID uint64
	parentPath string
	suffix     string
	instance   string // broker-minted child unit instance (also bound into the audit record)
	reqMask    uint32
	childMask  uint32
	created    time.Time
	decision   chan bool // buffered cap-1; resolve() sends exactly once, never blocks
	verdict    string    // "approve"|"deny"|"timeout"; set under pendMu before the send
	operator   string    // operator identity; set under pendMu before the send
}

var (
	pendMu     sync.Mutex
	pendNext   uint64
	pend       = map[uint64]*pending{}
	pendPerPar = map[uint64]int{}
	launchMu   sync.Mutex // serialize launchChild's daemon-reload/start (one PID-1 op at a time)
	brokerAL   *auditLog  // broker-owned signed decision chain (separate from the collector's)
)

// ---- broker (TCB listener) -------------------------------------------------

func cmdBroker() {
	// Self-register our own cgroup in the TCB allowlist so our bpf() map ops survive
	// E0 (lsm/bpf deny) and our own connects are E2-exempt. Requires E0 to be OFF at
	// this first call (the MVP default); see ADR-0006.
	if err := brokerSelfRegisterTCB(); err != nil {
		log.Fatalf("broker: self-register TCB (is the collector running?): %v", err)
	}
	// The broker owns its OWN signed decision chain (separate dir/key, via
	// BULKHEAD_AUDIT_DIR) — never the collector's single-writer provenance chain.
	al, err := openAuditLog()
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
	acceptLoop(delegLn, handleDelegate)
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

func brokerSelfRegisterTCB() error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "tcb_cgroups"), nil)
	if err != nil {
		return err
	}
	defer m.Close()
	cg, err := resolveCgroupID("self")
	if err != nil {
		return err
	}
	return m.Update(cg, uint32(1), ebpf.UpdateAny)
}

func handleDelegate(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second)) // a slow/hostile peer can't wedge the loop
	reply := func(s string) { fmt.Fprintln(conn, s) }

	// 1. Kernel-attested parent identity (NEVER from the request body).
	parentCgID, parentPath, err := peerParentCgID(conn)
	if err != nil {
		log.Printf("broker: peer-auth: %v", err)
		reply("ERR peer-auth")
		return
	}
	// Only a real jailed agent may delegate (and a TCB process must not use this path).
	if !strings.Contains(parentPath, "/bulkhead-agent.slice/bulkhead-agent@") {
		log.Printf("broker: reject non-agent parent cgroup %q", parentPath)
		reply("ERR not-an-agent")
		return
	}

	// 2. Request line: DELEGATE <child-suffix> <requested-classes>
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		reply("ERR read")
		return
	}
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) != 3 || f[0] != "DELEGATE" {
		reply("ERR protocol")
		return
	}
	suffix, reqStr := f[1], f[2]
	if !validSuffix(suffix) {
		reply("ERR bad-suffix")
		return
	}
	reqMask, err := parseClasses(reqStr)
	if err != nil {
		reply("ERR bad-classes")
		return
	}

	// 3. Parent's CURRENT ceiling from the live pinned map. Miss => cannot delegate
	//    (you cannot safely subset "unrestricted"). Fail-closed.
	parentMask, err := lookupEgressMask(parentCgID)
	if err != nil {
		reply("ERR no-parent-manifest")
		return
	}

	// 4. NARROW-NEVER-WIDEN: bitwise AND can only clear bits.
	childMask := parentMask & reqMask

	// 5. Human approval-gate (ADR-0007): block for an operator decision. Mint the child
	//    instance up front so LIST and the signed record can name it; extend the conn
	//    deadline to cover the (human-latency) approval wait.
	p := &pending{
		parentCgID: parentCgID, parentPath: parentPath, suffix: suffix,
		instance: "d-" + randHex8() + "-" + suffix, reqMask: reqMask, childMask: childMask,
		created: time.Now(),
	}
	_ = conn.SetDeadline(time.Now().Add(approvalTimeout + 15*time.Second))
	ok, verdict := approveDelegation(p)
	if !ok {
		reply("ERR " + verdict) // deny | timeout | busy — fail-closed, no child created
		return
	}

	// 6. Approved: launch the child jail; its +ExecStartPre writes the (narrowed)
	//    manifest in the child's own cgroup before the payload forks. Serialized.
	launchMu.Lock()
	lerr := launchChild(p.instance, classNames(childMask))
	launchMu.Unlock()
	if lerr != nil {
		log.Printf("broker: launch %s: %v", p.instance, lerr)
		reply("ERR launch")
		return
	}
	log.Printf("broker: delegated parent-cg=%d (mask 0x%02x) requested 0x%02x -> child %s mask 0x%02x (%s) [operator %s]",
		parentCgID, parentMask, reqMask, p.instance, childMask, classNames(childMask), p.operator)
	reply(fmt.Sprintf("OK %s %s", p.instance, classNames(childMask)))
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

// launchChild writes a transient /run drop-in carrying the narrowed manifest, then
// starts the jail instance. systemctl start blocks until the unit's +ExecStartPre (which
// writes egress_policy[child]) and ExecStart have run, so the broker only replies OK once
// the child's manifest is in the map — the child payload cannot connect() before that.
func launchChild(instance, classes string) error {
	unit := "bulkhead-agent@" + instance + ".service"
	dropDir := filepath.Join("/run/systemd/system", unit+".d")
	if err := os.MkdirAll(dropDir, 0o755); err != nil {
		return err
	}
	conf := "[Service]\nEnvironment=BULKHEAD_AGENT_EGRESS=" + classes + "\n"
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
func approveDelegation(p *pending) (bool, string) {
	if !register(p) {
		recordDecision(p, "deny", "broker:flood")
		return false, "busy"
	}
	timer := time.AfterFunc(approvalTimeout, func() { resolve(p.id, false, "timeout", "-") })
	ok := <-p.decision // single source of truth; verdict/operator set under lock before the send
	timer.Stop()
	recordDecision(p, p.verdict, p.operator)
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
		return "(no pending delegation requests)\n"
	}
	var b strings.Builder
	for _, p := range pend {
		fmt.Fprintf(&b, "id=%d parent=%s suffix=%s requested=%s granted=%s age=%ds\n",
			p.id, p.parentPath, p.suffix, classNames(p.reqMask), classNames(p.childMask),
			int(time.Since(p.created).Seconds()))
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
	default:
		fmt.Fprintln(conn, "ERR protocol")
	}
}

// recordDecision appends one signed record to the broker's OWN chain (never the
// collector's). Overloads provEvent's 6 fields: cgroup=parent, comm=child instance,
// hook="delegate", decision=verdict, mode="<operator> <req>-><grant>".
func recordDecision(p *pending, verdict, operator string) {
	if brokerAL == nil {
		return
	}
	comm := p.instance
	if len(comm) > 16 {
		comm = comm[:16]
	}
	ev := provEvent{
		CgroupID: p.parentCgID,
		PID:      0,
		Comm:     comm,
		Hook:     "delegate",
		Decision: verdict,
		Mode:     fmt.Sprintf("%s %s->%s", operator, classNames(p.reqMask), classNames(p.childMask)),
	}
	if err := brokerAL.append(ev); err != nil {
		log.Printf("broker: decision audit append: %v", err)
	}
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
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector delegate <child-suffix> <requested-classes>")
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
	if _, err := fmt.Fprintf(conn, "DELEGATE %s %s\n", args[0], args[1]); err != nil {
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
