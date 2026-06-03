# ADR-0012: TCB-context garbage collection of dead-agent policy map entries

Status: Accepted
Date: 2026-06-02
Relates to: ADR-0011 (one-shot E1/E3 privilege grant — this builds the TCB-context-cleanup
seam its adversarial review named, superseding the TTL as the authoritative backstop),
ADR-0010 (operator-initiated NARROW — the agent-slice glob + reverifyCgroup discipline reused
here), ADR-0006 (the broker's reverifyCgroup-gated, live-only map writes), ADR-0005 (the agent
jail unit carrying the ExecStopPost clears), ADR-0004 (the E0-E3 enforce model + the
TCB-exempt / deny-only / fail-open invariants this must preserve).

## Context

Per-agent BPF map entries (`grant_once[cg,hook]`, `egress_policy[cg]`) are cleaned up on agent
stop by the agent's OWN `ExecStopPost` on `bulkhead-agent@.service`:

    ExecStopPost=-+/usr/bin/bulkhead-collector egress clear self
    ExecStopPost=-+/usr/bin/bulkhead-collector grant-once clear self

Both do `bpf()` (`LoadPinnedMap` + `Delete`) from the agent's NON-TCB cgroup. When E0/`lsm-bpf`
is ARMED, `enforce_bpf` denies that `bpf()` (it denies on cgroup, not capability; the `+`
restores caps but NOT the cgroup), the leading `-` swallows the failure, and the entry is NOT
cleared. The clear is also skipped entirely if the agent CRASHES (SIGKILL/OOM, no clean stop).
A stranded `egress_policy` entry over-restricts a recycled cgroup (fail-SAFE); a stranded
`grant_once` entry over-permits (fail-DANGEROUS). ADR-0011 landed a TTL (default 300s) as an
E0-independent backstop and named the clean fix in its seam: a **TCB-context cleanup** that does
the delete from a process whose `bpf()` survives E0.

The collector (`bulkhead-collector run`) is the right home: it is ALWAYS running (not
socket-activated, unlike the broker), runs as root, self-registers root + its own cgroup into
`tcb_cgroups` at startup (so its `bpf()` is E0-exempt), already owns/pins the maps, and on
restart `os.RemoveAll(pinDir)` wipes everything (so the GC is for the steady state). The broker
is TCB too but socket-activated and, under E0-armed, a fresh broker cannot even self-register —
so the collector is the reliable cleanup owner.

## Decision

**A periodic-poll GC goroutine in the always-on collector.** `runCollector()` starts
`go gcLoop(stop)` AFTER the maps are pinned and `tcbCgroupIDs()` is registered (so the
collector's cgroup is E0-exempt) and BEFORE the ringbuf read loop. Every `gcInterval` (default
60s, `BULKHEAD_GC_INTERVAL` override, parsed like `grantTTL`) it recomputes the live agent-cgid
set and prunes dead-agent entries. The delete runs in the collector's process, so `enforce_bpf`
returns the TCB-exempt allow and the `bpf(BPF_MAP_DELETE_ELEM)` survives E0-armed — the entire
reason cleanup must live here, not in the agent.

**Poll, not event-driven, not a control-socket clear.** A full-recompute poll makes the safety
invariant ("no per-agent policy entry for a dead cgid") true regardless of HOW the entry
stranded — E0-blocked `ExecStopPost`, a crash that skipped it, or a leak during a collector
restart — because every pass reads the same ground truth: which agent dirs exist NOW. There is
no durable derived state to desync. Inotify is rejected: `IN_DELETE` fires AFTER the dir inode
is unlinked, so you cannot `stat` the dead cgid then; the fix (a pre-recorded dir->cgid table) is
empty across a collector restart and absent for a crashed agent, reintroducing exactly the
per-agent state the poll avoids. A control-socket clear from `ExecStopPost` is rejected: it
re-introduces the agent-context `bpf()` E0 blocks and still does nothing for a crash. Cost is
trivial: one glob of a handful of agent dirs plus two bounded `Iterate()`s
(`grant_once max_entries=256`, `egress_policy` small) every 60s.

**Live set (recomputed every pass).** `liveAgentCgids()` globs the agent slice with the SAME
three patterns `findAgentCgroupPath` uses (mirroring the `bulkhead.slice` nesting of ADR-0010),
generalized from a fixed leaf to `bulkhead-agent@*.service`, and `cgroupIDFromInode`s each match
(cgid == dir inode == `bpf_get_current_cgroup_id`). A dir that fails to stat (vanished mid-scan)
is skipped — the safe direction (treat as dead). Because the set is keyed by inode, a recycled
inode currently backing a live agent is in the set by construction and is never pruned.

**Prune predicates (delete-only).**
- `grant_once`: delete `{cgid,hook,pad}` iff `cgid NOT IN live`. No prefix gate — `grant_once`
  is structurally agent-gated (`handleBrokerConn` refuses any cgroup whose path lacks
  `/bulkhead-agent.slice/bulkhead-agent@` before `GRANT-ONCE` runs), so every key's cgid was
  born of an agent cgroup; "not a live agent cgid" == "dead agent cgid". This is the
  fail-DANGEROUS PRIMARY target.
- `egress_policy`: delete `cgid` iff `cgid NOT IN live` AND `cgid IN agentEgressSeen`.
  `agentEgressSeen` is an in-collector set grown each pass by adding every `egress_policy` key
  whose cgid is currently in `live` (provably agent-born). An entry set via
  `egress set <arbitrary-cgroup>` (tests/ops) is never under the agent slice, never enters
  `live`, never enters `agentEgressSeen`, and is NEVER pruned. This is the fail-SAFE SECONDARY
  target; the marker resolves the "a dead cgid's dir is gone, so its slice membership can't be
  re-derived" problem.

**`tcb_cgroups` and `enforce_flags` are NEVER touched.** The GC opens only `grant_once` and
`egress_policy` and only ever `Delete`s — it never `Update`s, never creates a key, never
grants/widens, never changes the TCB membership or arm posture. A GC error can therefore only
ever REMOVE a per-agent entry (fail-safe re-request), never add or widen one.

**ExecStopPost is KEPT as the prompt fast-path.** When E0 is OFF (the default observe posture,
the common case), the agent's own `+bpf()` succeeds and reclaims the entry IMMEDIATELY on clean
stop — latency ~0. The GC is the AUTHORITATIVE backstop for the two cases `ExecStopPost` cannot
cover: E0-armed (the clear is EPERM'd, `-` swallows it) and a crash (skips `ExecStopPost`
entirely). The two compose idempotently: both `Delete` the same dead key; whichever runs first
wins, the second is a harmless `ErrKeyNotExist` no-op (`grantClearSelf` and `egress clear`
already ignore it). This is exactly the layering ADR-0011 named — `ExecStopPost` as prompt
best-effort, the GC as the authoritative TCB backstop that now supersedes the TTL as the real
cleanup of record.

**Concurrency — disjoint by construction, no lock.** The broker (writer) and collector-GC
(deleter) are separate processes sharing only the pinned map. The broker writes a per-agent
entry ONLY inside `execute()` AFTER `reverifyCgroup` proves the dir inode equals the cgid (a LIVE
cgid); the GC deletes ONLY cgids NOT in `live` (DEAD). A cgid cannot be both live-at-reverify and
dead-at-scan, so the operations are disjoint, enforced by the kernel filesystem (both sides
consult the dir inode), not a mutex (which cannot exist across processes). The sub-interval
TOCTOU degrades to outcomes already handled: a late `grant_once` `UpdateAny` for an agent that
exited mid-approval re-creates a dead-cgid key the next pass + the TTL reclaim; a late
`egress_policy` `UpdateExist` fails closed because the GC already deleted the key (the broker
correctly refuses to resurrect a vanished agent's manifest). The pass collects dead keys during
`Iterate` and `Delete`s them in a second loop, avoiding any iterator-invalidation assumption on
the kernel hash map.

**Restart-consistent.** `runCollector`'s `os.RemoveAll(pinDir)` wipes both maps on every start,
so the in-memory `agentEgressSeen` starting empty after a restart cannot strand an orphan.

## Verification

Host `go test -race` (pure-Go via an injected live set + map handles passed to a shared
`runGCPass(live, gm, ep, seen)`): `TestGCPrunePredicateGrantOnce` (dead cg's keys selected, live
cg's kept, recycled cg in both live and map kept), `TestGCEgressMarkerGate` (only a
seen-and-now-dead agent egress cgid pruned; a never-seen non-agent cgid immune; proves the
`egress set <arbitrary-cgroup>` invariant), `TestLiveAgentCgidsGlob` (a `t.TempDir()` fake
agent-slice tree, vanished dir skipped, redirecting the package-var glob roots),
`TestGCNeverTouchesTcbOrEnforce` (structural — only `grant_once`+`egress_policy` handles, only
`Delete` ops), `TestGCInterval` (env parse positive/zero/garbage -> default).

A deterministic `bulkhead-collector gc` subcommand (new case in `main()`'s switch beside
`status`) runs ONE `runGCPass` synchronously against the pinned maps and prints machine-checkable
lines (`gc: pruned grant_once cg=<id> hook=<name>`, `gc: pruned egress_policy cg=<id>`) plus a
summary, then exits 0 — no timer, no broker, no console-lockout fight. The same `runGCPass` backs
the goroutine and the subcommand, so the qemu assertion exercises the production logic. NB: run
from a non-TCB console cgroup the subcommand's own `bpf()` is itself E0-blockable, so under
E0-armed the AUTHORITATIVE path is the in-collector loop; the subcommand is fully authoritative
for the E0-off deterministic arms and for `grant_once` (structurally agent-gated, no marker), and
best-effort for a fully-vanished agent's `egress` (its dead cgid can't be re-classified) — so the
egress assertion drives the loop, where `agentEgressSeen` persists.

qemu (extends ADR-0011's harness; E1/E3 armed first, plus an E0-ARMED arm — the whole point):
**(1) E0-armed stranded grant (headline)** — arm E0, grant-once+approve (unconsumed),
`systemctl stop` so the agent's `ExecStopPost` clear is EPERM'd and the grant strands; with a low
`BULKHEAD_GC_INTERVAL` the in-collector `gcLoop` deletes it (`status` zero, journal shows
`gc: pruned grant_once`), even though the agent's own `bpf()` is denied. **(2) crash** —
`systemctl kill -s SIGKILL` (skips `ExecStopPost`), `bulkhead-collector gc`, assert reclaimed.
**(3) never-prune-live** — while an agent runs, `gc` reports 0 pruned, entries intact. **(4)
recycle-onto-live** — a new agent on the same inode is NOT pruned (in `live`). **(5) egress
non-agent immunity** — `egress set id:<non-agent>` is never pruned by the loop, while a dead
agent's egress is. **(6) exactly-one** — one dead + one live grant: `gc` prunes exactly the dead
one. Plus: assert `enforce_flags`/`tcb_cgroups` byte-identical before/after, `status` counts only
drop-or-hold, and re-run the E0-E3 regression to confirm the BPF object is byte-for-byte unchanged
(pure-Go change, no `.o` delta, no new map).

## Seam left clean

`grant_once` GC is fully authoritative (structural agent-gating, no marker, restart-robust via
`RemoveAll`). `egress_policy` GC is authoritative only via the steady-state loop, gated on the
in-memory `agentEgressSeen` provenance set; the one-shot `gc` subcommand is best-effort for a
fully-vanished agent's egress because a gone cgid cannot be re-classified as ex-agent. A cleaner
future fix is to make agent-born egress self-identifying without in-memory state — a companion
pinned set written by `egress set self`, or a structural tag — so the egress GC becomes
restart-robust and subcommand-authoritative; deliberately NOT done here because it changes the
egress ABI / adds a map (this ADR is no-new-BPF, no-new-map). Also deferred: a tighter
event-driven trigger (rejected on the IN_DELETE-after-inode-gone + crash/restart-miss grounds
above) and exposing `gc` as an in-collector control poke so the subcommand always deletes in
TCB context (deferred — it adds a socket this design avoids). The TTL (ADR-0011) remains as a
second, E0-independent layer below the GC.

NOTE on packaging: the Buildroot prototype `.mk` builds from `src/collector` directly (local, no
SRCREV). The **Yocto** production recipe (`meta-bulkhead/recipes-bulkhead/bulkhead-collector`)
fetches the repo at a pinned `SRCREV`, so — as for every prior collector change — this commit must
be pushed and the collector recipe SRCREV bumped before the qemu image picks up `gc.go`. No BPF
object regen (pure-Go change; the committed `.o` is untouched); `bulkhead-units` is unchanged
(the agent template keeps both ExecStopPost clears as the E0-off fast-path), so only the collector
SRCREV moves.