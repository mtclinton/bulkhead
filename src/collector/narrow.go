// SPDX-License-Identifier: AGPL-3.0-only
package main

// ADR-0010: operator-initiated egress NARROW — the operator-initiated DUAL of ADR-0009's
// agent-requested EXPAND. An operator (uid-0, the existing approve.sock authority) clamps a
// NAMED, running agent's egress manifest to `live &^ classes` IMMEDIATELY and IN PLACE,
// without killing the agent — incident response: throttle a misbehaving agent's egress now.
//
// Operator-DIRECT, NOT gated: the operator is the authority the approval gate exists to
// consult, so a narrow runs synchronously inside handleApprove after the SO_PEERCRED uid==0
// check — no pending, no decision channel, no 120s window during which the agent keeps its
// egress. It still re-verifies identity (reverifyCgroup) and still signs one record to the
// broker decision chain. No new BPF/map: the verified E0-E3 object is byte-for-byte unchanged.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

// narrowMask clears the requested class bits — the exact complement of expandMask. It is
// monotone-decreasing (can never SET a bit), so no ceiling is meaningful or applied;
// requesting a class the agent lacks is a no-op on that class.
func narrowMask(cur, req uint32) uint32 { return cur &^ req }

// Target-resolution sentinels so handleNarrow can map to precise operator replies.
var (
	errNarrowID       = errors.New("id: form not allowed for narrow")
	errNarrowBadInst  = errors.New("bad target instance")
	errNarrowNotAgent = errors.New("not an agent cgroup")
	errNarrowGone     = errors.New("target cgroup not found")
)

// validInstance accepts a systemd instance tail (charset a-z0-9-_ only, so no path traversal
// — no '/' or '.'), longer than validSuffix's 24-char delegation cap so broker-minted child
// instances (d-<hex>-<suffix>) remain addressable by name.
func validInstance(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// resolveAgentTarget maps an operator-supplied target to a live agent cgroup id + the cgroup
// path (relative to /sys/fs/cgroup, the form reverifyCgroup expects). It REFUSES anything
// that does not resolve to a cgroup under /bulkhead-agent.slice/bulkhead-agent@ so narrow can
// never clamp the collector, the broker, PID-1/root, or the operator's own session.scope.
// Accepts a bare <inst>, bulkhead-agent@<inst>.service, or an absolute /sys/fs/cgroup/… (or
// /…) agent-slice path. The id:N form is refused — a bare id cannot be checked against the
// slice. The predicate is checked on the CLEANED absolute path, so a `..` traversal that
// escapes the agent slice fails closed.
func resolveAgentTarget(target string) (uint64, string, error) {
	if strings.HasPrefix(target, "id:") {
		return 0, "", errNarrowID
	}
	var rel string // path relative to /sys/fs/cgroup
	switch {
	case strings.HasPrefix(target, "/sys/fs/cgroup"):
		rel = strings.TrimPrefix(target, "/sys/fs/cgroup")
	case strings.HasPrefix(target, "/"):
		rel = target
	default:
		inst := strings.TrimSuffix(strings.TrimPrefix(target, "bulkhead-agent@"), ".service")
		if !validInstance(inst) {
			return 0, "", errNarrowBadInst
		}
		// Don't hardcode the slice hierarchy: systemd nests bulkhead-agent.slice under its
		// dash-derived parent (bulkhead.slice), so the live path is
		// /bulkhead.slice/bulkhead-agent.slice/bulkhead-agent@<inst>.service. Glob for the
		// real cgroup dir of a RUNNING instance; no match (not running) => target-gone.
		rel = findAgentCgroupPath(inst)
		if rel == "" {
			return 0, "", errNarrowGone
		}
	}
	full := filepath.Clean(filepath.Join("/sys/fs/cgroup", rel))
	if !strings.Contains(full, "/bulkhead-agent.slice/bulkhead-agent@") {
		return 0, "", errNarrowNotAgent
	}
	cgID, err := cgroupIDFromInode(full)
	if err != nil {
		return 0, "", errNarrowGone
	}
	return cgID, strings.TrimPrefix(full, "/sys/fs/cgroup"), nil
}

// findAgentCgroupPath locates a RUNNING agent instance's cgroup directory (path relative to
// /sys/fs/cgroup) without hardcoding the slice nesting, returning "" if not found/ambiguous.
// systemd derives bulkhead-agent.slice's parent from its name, so the dir lives one level
// under bulkhead.slice; the `*` pattern also tolerates a different single-level parent.
func findAgentCgroupPath(inst string) string {
	leaf := "bulkhead-agent@" + inst + ".service"
	for _, pat := range []string{
		"/sys/fs/cgroup/bulkhead.slice/bulkhead-agent.slice/" + leaf,
		"/sys/fs/cgroup/*/bulkhead-agent.slice/" + leaf,
		"/sys/fs/cgroup/bulkhead-agent.slice/" + leaf,
	} {
		if ms, _ := filepath.Glob(pat); len(ms) == 1 {
			return strings.TrimPrefix(ms[0], "/sys/fs/cgroup")
		}
	}
	return ""
}

// handleNarrow runs the operator-direct clamp. Called from handleApprove ONLY (the uid==0
// SO_PEERCRED check already gated it). Reply protocol mirrors the broker's OK/ERR lines.
func handleNarrow(conn net.Conn, operator string, f []string) {
	reply := func(s string) { fmt.Fprintln(conn, s) }
	if len(f) != 3 {
		reply("ERR protocol")
		return
	}
	reqMask, err := parseClasses(f[2])
	if err != nil {
		reply("ERR bad-classes")
		return
	}
	cgID, cgPath, err := resolveAgentTarget(f[1])
	if err != nil {
		switch {
		case errors.Is(err, errNarrowID):
			reply("ERR id-not-allowed")
		case errors.Is(err, errNarrowBadInst):
			reply("ERR bad-target")
		case errors.Is(err, errNarrowNotAgent):
			reply("ERR not-an-agent")
		default:
			reply("ERR target-gone")
		}
		return
	}

	// Serialize with EXPAND (both RMW egress_policy); see egressMu.
	egressMu.Lock()
	defer egressMu.Unlock()

	// Trust ONLY live-re-derived identity (the project rule): re-stat the named target's
	// cgroup and clamp the RIGHT live inode, fail closed on recycle/vanish. The operator's
	// typed name is advisory.
	if err := reverifyCgroup(cgPath, cgID); err != nil {
		recordNarrow(cgID, f[1], reqMask, "error", operator, "(target recycled/gone)")
		reply("ERR target-gone")
		return
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "egress_policy"), nil)
	if err != nil {
		recordNarrow(cgID, f[1], reqMask, "error", operator, "(map open failed)")
		reply("ERR internal")
		return
	}
	defer m.Close()

	var live uint32
	if err := m.Lookup(cgID, &live); err != nil {
		// No manifest == unrestricted: REFUSE (symmetric to EXPAND). Creating an entry would
		// clamp the agent to the named-complement (every unset class flips to deny once E2
		// bites) — a create-surprise. Use `egress set <target> <complement>` to create one.
		recordNarrow(cgID, f[1], reqMask, "error", operator, "(no-manifest)")
		reply("ERR no-manifest")
		return
	}
	final := narrowMask(live, reqMask)
	if final == live { // no held class requested — don't churn the map, but still record it
		if err := recordNarrow(cgID, f[1], reqMask, "narrow-noop", operator, classNames(live)); err != nil {
			log.Printf("broker: AUDIT APPEND FAILED for narrow-noop cg=%d: %v", cgID, err)
			reply("ERR audit")
			return
		}
		reply("OK " + f[1] + " " + classNames(live) + " (no-op)")
		return
	}
	if err := m.Update(cgID, final, ebpf.UpdateExist); err != nil {
		_ = recordNarrow(cgID, f[1], reqMask, "error", operator, "(update failed)")
		reply("ERR target-gone") // UpdateExist: refuse to CREATE on a recycled/cleared key
		return
	}
	// F7: the clamp landed; the signed record is load-bearing. If the append fails, surface
	// it (ERR audit) rather than claiming OK on an unrecorded privileged change.
	if err := recordNarrow(cgID, f[1], reqMask, "narrow", operator, classNames(final)); err != nil {
		log.Printf("broker: AUDIT APPEND FAILED after applied narrow cg=%d -> %s: %v", cgID, classNames(final), err)
		reply("ERR audit")
		return
	}
	log.Printf("broker: narrow cg=%d %s -> %s [operator %s]", cgID, f[1], classNames(final), operator)
	reply("OK " + f[1] + " " + classNames(final))
}

// recordNarrow appends ONE signed record to the broker's OWN decision chain, AFTER the map op
// so `applied` reflects the actually-applied state (F4). Operator-initiated, so there is no
// requester pidfd: CgroupID is the RE-VERIFIED target; operator is the SO_PEERCRED uid:pid.
func recordNarrow(cgID uint64, target string, reqMask uint32, verdict, operator, applied string) error {
	if brokerAL == nil {
		return nil
	}
	comm := target
	if len(comm) > 16 {
		comm = comm[:16]
	}
	mode := fmt.Sprintf("%s req=%s applied=%s", operator, classNames(reqMask), applied)
	ev := provEvent{CgroupID: cgID, PID: 0, Comm: comm, Hook: string(actNarrowEgress), Decision: verdict, Mode: mode}
	return brokerAL.append(ev)
}

// cmdNarrow is the operator CLI: bulkhead-collector narrow <target> <classes>. It dials the
// uid-0 approve.sock exactly like cmdApprove; the kernel SO_PEERCRED check rejects any
// non-root caller. Synchronous + immediate — no approval-timeout deadline math.
func cmdNarrow(args []string) {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector narrow <instance|agent-slice-path> <classes>")
		os.Exit(2)
	}
	conn, err := net.DialTimeout("unix", approveSockPath, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "narrow: dial: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "NARROW %s %s\n", args[0], args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "narrow: send: %v\n", err)
		os.Exit(1)
	}
	b, _ := io.ReadAll(conn)
	os.Stdout.Write(b)
	if bytes.Contains(b, []byte("ERR")) {
		os.Exit(1)
	}
}
