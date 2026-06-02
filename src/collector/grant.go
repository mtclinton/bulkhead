// SPDX-License-Identifier: AGPL-3.0-only
package main

// ADR-0011: kernel-enforced one-shot E1/E3 privilege grant. When E1 (ptrace) or E3
// (setuid/capset) is ARMED an agent is normally denied; this is a human-gated SINGLE-USE
// exception. An agent asks the broker for ONE <ptrace|setuid|capset>; the operator approves;
// the broker writes a one-use entry into the pinned grant_once map; the BPF hook atomically
// consumes it (CAS 1->0) on its next would-deny, allowing exactly that one op. Gated (agent
// requests -> operator approves), mirroring actExpandEgress; E0 (bpf) is NOT grantable.

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

// grantableHook resolves a hook name to its id ONLY for the one-shot-grantable hooks
// (E1 ptrace, E3 setuid/capset). E0 bpf (the substrate) and E2 socket_connect are refused.
func grantableHook(name string) (uint32, bool) {
	hid, ok := hookID(name)
	if !ok || (hid != hookPtrace && hid != hookSetuid && hid != hookCapset) {
		return 0, false
	}
	return hid, true
}

// hookArmed reports whether a hook's enforce flag is set (a map miss => observe => false).
func hookArmed(hid uint32) (bool, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "enforce_flags"), nil)
	if err != nil {
		return false, err
	}
	defer m.Close()
	var v uint32
	if err := m.Lookup(hid, &v); err != nil {
		return false, nil // miss => observe
	}
	return v == 1, nil
}

// handleGrantOnceTail: GRANT-ONCE <hook> — the requester asks for ONE otherwise-denied E1/E3
// op on ITS OWN kernel-attested cgroup. Only ptrace/setuid/capset are grantable; bpf (E0) and
// socket_connect (E2) are refused. The grant write happens in execute() — ONLY after operator
// approval — re-verifying the live cgroup first (the project rule).
func handleGrantOnceTail(conn net.Conn, agentCgID uint64, agentPath string, f []string) {
	reply := func(s string) { fmt.Fprintln(conn, s) }
	if len(f) != 2 {
		reply("ERR protocol")
		return
	}
	hid, ok := grantableHook(f[1])
	if !ok {
		reply("ERR bad-hook") // E0 bpf + E2 socket_connect are NOT one-shot-grantable
		return
	}
	// Don't burn an operator decision (or let an agent flood the queue) for an unarmed hook:
	// with the hook in observe the op is already allowed, so a grant would be a no-op.
	if armed, err := hookArmed(hid); err == nil && !armed {
		reply("OK " + f[1] + " (not-armed, no-op)")
		return
	}
	cgID := agentCgID
	hook := hid
	p := &pending{
		kind: actGrantOnce, parentCgID: agentCgID, parentPath: agentPath,
		grantHook: hid, created: time.Now(),
	}
	p.execute = func(p *pending) (string, error) {
		grantMu.Lock()
		defer grantMu.Unlock()
		// Re-bind to the live cgroup before granting (a request that outlived its agent fails
		// closed). A grant CREATES the key (UpdateAny), unlike EXPAND/NARROW's UpdateExist —
		// the recycle defense here is reverifyCgroup + ExecStopPost clear, not UpdateExist.
		if err := reverifyCgroup(p.parentPath, cgID); err != nil {
			return "", err
		}
		m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "grant_once"), nil)
		if err != nil {
			return "", err
		}
		defer m.Close()
		k := bpfGrantKey{Cgid: cgID, Hook: hook}
		v := bpfGrantVal{Count: 1, ExpireNs: 0} // SET=1, never increment (no count inflation)
		if err := m.Update(k, v, ebpf.UpdateAny); err != nil {
			return "", err
		}
		return hookNames[hook] + " count=1", nil
	}
	_ = conn.SetDeadline(time.Now().Add(approvalTimeout + 15*time.Second))
	finishGated(conn, p)
}

// cmdGrantOnce is the agent CLI: `grant-once <ptrace|setuid|capset>` (blocks across the
// approval gate, like expand) and `grant-once clear self` (ExecStopPost hygiene).
func cmdGrantOnce(args []string) {
	if len(args) == 2 && args[0] == "clear" && args[1] == "self" {
		grantClearSelf()
		return
	}
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector grant-once <ptrace|setuid|capset> | grant-once clear self")
		os.Exit(2)
	}
	conn, err := net.DialTimeout("unix", brokerSockPath, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "grant-once: dial broker: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	// Deadline must exceed the broker's approval timeout so its definite OK/ERR lands first.
	to := 180 * time.Second
	if v := os.Getenv("BULKHEAD_GRANT_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			to = time.Duration(n) * time.Second
		}
	}
	_ = conn.SetDeadline(time.Now().Add(to))
	if _, err := fmt.Fprintf(conn, "GRANT-ONCE %s\n", args[0]); err != nil {
		fmt.Fprintf(os.Stderr, "grant-once: send: %v\n", err)
		os.Exit(1)
	}
	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "grant-once: read reply: %v\n", err)
		os.Exit(1)
	}
	resp = strings.TrimSpace(resp)
	fmt.Println(resp)
	if !strings.HasPrefix(resp, "OK ") {
		os.Exit(1)
	}
}

// grantClearSelf deletes ALL of this cgroup's one-shot grant keys. Run by the agent's
// ExecStopPost (+CAP_BPF) so an UNCONSUMED grant can never be inherited by a recycled
// cgroup. Best-effort: a missing key/map is fine (the ExecStopPost uses a `-` prefix).
func grantClearSelf() {
	cg, err := resolveCgroupID("self")
	if err != nil {
		return
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "grant_once"), nil)
	if err != nil {
		return
	}
	defer m.Close()
	for _, h := range []uint32{hookPtrace, hookSetuid, hookCapset} {
		_ = m.Delete(bpfGrantKey{Cgid: cg, Hook: h})
	}
}
