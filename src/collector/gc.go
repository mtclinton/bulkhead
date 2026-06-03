// SPDX-License-Identifier: AGPL-3.0-only
package main

// ADR-0012: TCB-context garbage collection of per-agent BPF map entries. ADR-0011's recycle
// hygiene relies on the agent's OWN ExecStopPost (`grant-once clear self` / `egress clear
// self`), which does bpf() from the agent's NON-TCB cgroup — so it is silently EPERM'd when
// E0/lsm-bpf is armed, and skipped entirely if the agent crashes. This GC runs in the
// always-on collector process, whose cgroup is in tcb_cgroups (so its bpf() Delete survives
// E0), and does a periodic FULL RECOMPUTE: it stats the live agent-slice cgroup dirs (cgid =
// dir inode) and deletes per-agent map entries for cgids with no live cgroup. A full-recompute
// poll is self-healing — it reclaims a stranded entry regardless of HOW it stranded (E0-blocked
// clear, a crash that skipped ExecStopPost, or a leak during a collector-restart window) — and
// is DELETE-ONLY: it can only ever REMOVE a dead agent's policy entry (fail-safe), never grant
// or widen one, and never touches tcb_cgroups/enforce_flags. No new BPF; the E0-E3 object is
// byte-for-byte unchanged. The ExecStopPost clears are kept as the prompt E0-off fast-path.

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
)

// gcInterval is the GC poll period. Default 60s (well under the 300s default grant TTL, so the
// GC is the effective E0-robust backstop); BULKHEAD_GC_INTERVAL (seconds) overrides.
var gcInterval = parseGCInterval(os.Getenv("BULKHEAD_GC_INTERVAL"))

func parseGCInterval(v string) time.Duration {
	if v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 60 * time.Second
}

// agentSliceGlobs locate every live agent instance's cgroup dir (its inode == cgid). The same
// patterns + bulkhead.slice nesting as narrow.go's findAgentCgroupPath, generalized from a
// fixed leaf to the @*.service wildcard. A package var so tests can redirect the roots.
var agentSliceGlobs = []string{
	"/sys/fs/cgroup/bulkhead.slice/bulkhead-agent.slice/bulkhead-agent@*.service",
	"/sys/fs/cgroup/*/bulkhead-agent.slice/bulkhead-agent@*.service",
	"/sys/fs/cgroup/bulkhead-agent.slice/bulkhead-agent@*.service",
}

// liveAgentCgids returns the cgroup ids (dir inodes) of every CURRENTLY-live agent instance.
// A match that fails to stat (vanished mid-scan) is skipped — treated as dead, the safe
// direction. Because the set is keyed by the inode that exists NOW, a recycled inode currently
// backing a live agent dir is in the set by construction and can never be pruned.
func liveAgentCgids() map[uint64]struct{} {
	live := map[uint64]struct{}{}
	for _, pat := range agentSliceGlobs {
		ms, _ := filepath.Glob(pat)
		for _, m := range ms {
			if id, err := cgroupIDFromInode(m); err == nil {
				live[id] = struct{}{}
			}
		}
	}
	return live
}

// runGCPass deletes per-agent map entries for dead cgids. DELETE-ONLY; never Update/create;
// never touches tcb_cgroups/enforce_flags. Returns what it deleted (for logging + `gc`).
//
//   - grant_once: delete key iff its cgid is NOT live. No provenance gate is needed — GRANT-ONCE
//     is structurally agent-gated (handleBrokerConn rejects any non-agent cgroup before a grant
//     is written), so every grant cgid is agent-born; not-live == a dead agent. (Fail-DANGEROUS
//     target — a stranded grant over-permits.)
//   - egress_policy: delete key iff its cgid is NOT live AND was previously WITNESSED live under
//     the agent slice (in `seen`). egress_policy legitimately holds arbitrary non-agent cgids
//     (`egress set <cgroup>`), which are never seen live as an agent, so are never pruned.
//     `seen` grows with every live agent egress cgid this pass. (Fail-safe secondary target.)
func runGCPass(live map[uint64]struct{}, gm, ep *ebpf.Map, seen map[uint64]struct{}) (grantDel []bpfGrantKey, egressDel []uint64) {
	if gm != nil {
		var keys []bpfGrantKey
		var k bpfGrantKey
		var v bpfGrantVal
		it := gm.Iterate()
		for it.Next(&k, &v) { // collect-then-delete: never mutate the map under its iterator
			keys = append(keys, k)
		}
		grantDel = selectGrantPrunes(keys, live)
		for _, dk := range grantDel {
			if err := gm.Delete(dk); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				log.Printf("gc: delete grant_once cg=%d hook=%d: %v", dk.Cgid, dk.Hook, err)
			}
		}
	}
	if ep != nil {
		var cgids []uint64
		var cgid uint64
		var mask uint32
		it := ep.Iterate()
		for it.Next(&cgid, &mask) {
			cgids = append(cgids, cgid)
		}
		egressDel = selectEgressPrunes(cgids, live, seen)
		for _, dc := range egressDel {
			if err := ep.Delete(dc); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				log.Printf("gc: delete egress_policy cg=%d: %v", dc, err)
			}
		}
	}
	return grantDel, egressDel
}

// selectGrantPrunes returns the grant keys whose cgid is NOT live — a dead agent's grant (every
// grant cgid is agent-born by construction). Pure; the safety-critical predicate.
func selectGrantPrunes(keys []bpfGrantKey, live map[uint64]struct{}) []bpfGrantKey {
	var del []bpfGrantKey
	for _, k := range keys {
		if _, ok := live[k.Cgid]; !ok {
			del = append(del, k)
		}
	}
	return del
}

// selectEgressPrunes returns the egress cgids to prune — dead AND previously witnessed live
// under the agent slice (in `seen`) — and grows `seen` with the cgids that are live THIS pass.
// A cgid never seen live as an agent (e.g. an ops `egress set <cgroup>`) is never pruned. Pure.
func selectEgressPrunes(cgids []uint64, live, seen map[uint64]struct{}) []uint64 {
	var del []uint64
	for _, cg := range cgids {
		if _, ok := live[cg]; ok {
			seen[cg] = struct{}{}
		} else if _, was := seen[cg]; was {
			del = append(del, cg)
		}
	}
	return del
}

// brokerCgroupPath is the broker service's cgroup dir; its inode is the broker cgid that must
// stay in tcb_cgroups. The broker has no custom Slice=, so it lives directly under system.slice
// — the SAME path the broker's own resolveCgroupID("self") computes when it self-registers. A
// package var so tests can redirect it.
var brokerCgroupPath = "/sys/fs/cgroup/system.slice/bulkhead-broker.service"

// reconcileTCB prunes any tcb_cgroups entry that is not {root, the collector, the LIVE broker}.
// Composed-review fix: the broker self-registers its cgid once and never deletes it, so an
// independent broker re-activation leaves a STALE cgid in tcb_cgroups whose dead inode can be
// recycled onto a bulkhead-agent@ jail — granting that agent full E0-E3 TCB exemption (the one
// per-cgroup map with no other recycle defense). The collector (always-on, TCB, E0-exempt)
// reconciles it here. FAIL-SAFE: if root+collector cannot be resolved it prunes NOTHING (never
// blindly empties the map); the live broker is in the keep-set (resolved by the same path the
// broker self-registers), so the working broker is never pruned. DELETE-ONLY (never adds — the
// broker self-registers itself, always under E0-off since agents/the broker can't start under
// E0-armed).
func reconcileTCB(tcb *ebpf.Map) (pruned []uint64) {
	keep := map[uint64]struct{}{}
	for _, id := range tcbCgroupIDs() { // root + the collector's own cgroup
		keep[id] = struct{}{}
	}
	if len(keep) < 2 {
		return nil // could not resolve root+collector -> never prune blindly
	}
	if bid, err := cgroupIDFromInode(brokerCgroupPath); err == nil {
		keep[bid] = struct{}{} // the live broker
	}
	var key uint64
	var val uint32
	it := tcb.Iterate()
	for it.Next(&key, &val) {
		if _, ok := keep[key]; !ok {
			pruned = append(pruned, key)
		}
	}
	for _, k := range pruned {
		if err := tcb.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Printf("gc: tcb prune cg=%d: %v", k, err)
		}
	}
	return pruned
}

// gcLoop is the authoritative, E0-robust GC: a ticker in the collector process. It holds the
// process-local `seen` set (agent-born egress cgids witnessed live) across ticks; restart is
// safe because runCollector os.RemoveAll(pinDir) wipes egress_policy on the same start.
func gcLoop(stop <-chan struct{}) {
	seen := map[uint64]struct{}{}
	t := time.NewTicker(gcInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			gm, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "grant_once"), nil)
			if err != nil {
				continue
			}
			ep, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "egress_policy"), nil)
			if err != nil {
				gm.Close()
				continue
			}
			live := liveAgentCgids()
			gd, ed := runGCPass(live, gm, ep, seen)
			gm.Close()
			ep.Close()
			for _, k := range gd {
				log.Printf("gc: pruned grant_once cg=%d hook=%s", k.Cgid, hookNames[k.Hook])
			}
			for _, cg := range ed {
				log.Printf("gc: pruned egress_policy cg=%d", cg)
			}
			var tp []uint64
			if tcb, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "tcb_cgroups"), nil); err == nil {
				tp = reconcileTCB(tcb)
				tcb.Close()
				for _, cg := range tp {
					log.Printf("gc: pruned STALE tcb_cgroup cg=%d (recycle-escape guard)", cg)
				}
			}
			if len(gd) > 0 || len(ed) > 0 || len(tp) > 0 {
				log.Printf("gc: pruned %d grant_once + %d egress_policy + %d tcb_cgroups (live agents: %d)", len(gd), len(ed), len(tp), len(live))
			}
		}
	}
}

// cmdGC runs ONE deterministic GC pass and reports it — the test/ops trigger. NB: run from a
// console it executes its own bpf() Delete from a NON-TCB cgroup, so it is NOT E0-robust (the
// in-collector gcLoop is). It is authoritative for grant_once (provenance is structural) under
// E0-off; egress pruning needs the loop's persistent `seen`, so a one-shot pass (fresh `seen`)
// will not prune a dead egress entry it never witnessed live — by design.
func cmdGC() {
	gm, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "grant_once"), nil)
	if err != nil {
		log.Fatalf("gc: open grant_once (is the collector running?): %v", err)
	}
	defer gm.Close()
	ep, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "egress_policy"), nil)
	if err != nil {
		log.Fatalf("gc: open egress_policy: %v", err)
	}
	defer ep.Close()
	live := liveAgentCgids()
	gd, ed := runGCPass(live, gm, ep, map[uint64]struct{}{})
	for _, k := range gd {
		fmt.Printf("gc: pruned grant_once cg=%d hook=%s\n", k.Cgid, hookNames[k.Hook])
	}
	for _, cg := range ed {
		fmt.Printf("gc: pruned egress_policy cg=%d\n", cg)
	}
	fmt.Printf("gc: pruned %d grant_once, %d egress_policy (live agents: %d)\n", len(gd), len(ed), len(live))
}
