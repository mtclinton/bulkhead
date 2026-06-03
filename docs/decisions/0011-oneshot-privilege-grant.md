# ADR-0011: Kernel-enforced one-shot E1/E3 privilege grant

Status: Accepted
Date: 2026-06-02
Relates to: ADR-0009 (generalized approval-gate + EXPAND — this builds the "concrete next:
one-shot E1/E3 privilege grants" seam it named), ADR-0010 (operator-initiated NARROW — the
ungated dual; this is gated), ADR-0007 (the human approval-gate), ADR-0004 (the E0-E3 enforce
model + the fail-open/TCB/deny-only/observe invariants this must preserve).

## Context

When E1 (ptrace_access_check) or E3 (task_fix_setuid / capset) is ARMED, a non-TCB agent is
DENIED the corresponding privileged op. Some legitimate one-off operations (a debugger attach,
a single regain-root) need a human-authorized exception WITHOUT disarming the hook fleet-wide
and WITHOUT moving the agent into the TCB. ADR-0009 named this the "concrete next" gated action.

This adds `grant-once`: an agent runs `bulkhead-collector grant-once <ptrace|setuid|capset>`,
the operator approves on the uid-0 `approve.sock`, and the broker writes a single-use grant into
a NEW pinned BPF map. The grant is ENFORCED IN THE KERNEL — the E1/E3 hook checks the map on its
would-deny path and ATOMICALLY consumes exactly one use, flipping that single op denied->allowed;
the next op is denied again. It is gated (agent->human), the dual posture of ADR-0010's NARROW.

This is the FIRST change to the verified E0-E3 BPF object since E3. The verified invariants
(fail-open, TCB-exempt, deny-only/one-way-ratchet, observe-logging) are preserved by construction,
and E0 (lsm/bpf — the substrate the TCB rests on) is NOT grantable.

## Decision

**New pinned map `grant_once`** at `/sys/fs/bpf/bulkhead/grant_once`:
`BPF_MAP_TYPE_HASH`, `max_entries=256`, key `struct grant_key { __u64 cgid; __u32 hook; __u32 _pad; }`
(16B, explicit pad so loader/compiler agree on a deterministic key with no uninit bytes — the same
discipline as the fixed-offset probe_reads), value `struct grant_val { __u64 count; __u64
expire_ns; }` (16B). `count` is a **`__u64`** — the BPF backend (`-mcpu=v1`) only lowers a 64-bit
compare-and-swap (`clang` rejects a 32-bit one with "unsupported atomic operation, please use 64
bit version"). The hook id is a FIRST-CLASS KEY COMPONENT, so per-hook isolation is
structural: a ptrace grant `{cg,HOOK_PTRACE}` is a physically different entry from a setuid grant
`{cg,HOOK_SETUID}`, and a consume in `enforce_ptrace` can never touch the setuid entry. One map,
one pin, one status section. Rejected: struct-of-counts keyed by cgid (couples three independent
grants into one value, makes the consume a sub-field CAS or a spin_lock — more verifier surface,
worse per-hook isolation) and N-maps-per-hook (triples pins/boilerplate/bpf2go churn for no gain;
per-hook granularity needs the hook IN THE KEY, not a map per hook).

**Atomic exactly-once consume — CAS `1->0`, never `fetch_and_sub`.** On the would-deny path only,
`try_consume_grant(cg,hook)` looks up the key and does
`__sync_val_compare_and_swap(&v->count, 1, 0) == 1`; the single winner gets allow and then
`bpf_map_delete_elem`s the key (no count==0 zombie). `fetch_and_sub` is rejected: on an already-0
or stale value it underflows to `0xffffffff` — a permanent grant. CAS resolves N racing agent
threads to exactly one winner, can never go negative (we only ever swap to a fixed 0), and a
double-consume is impossible (the second CAS sees `0 != 1` and fails). `bpf_spin_lock` is rejected:
it needs a `struct bpf_spin_lock` member in the value + lock/unlock calls — strictly more verifier
surface and value-layout churn for a single-word test-and-clear.

**E0 ungrantable BY CONSTRUCTION.** `enforce_verdict(hook,ret)` is split into the original
non-consuming body plus a grant-aware `enforce_verdict_g(hook, ret, grantable)`.
`enforce_bpf` calls `enforce_verdict(HOOK_BPF, ret)` — semantically unchanged — which forwards
`enforce_verdict_g(HOOK_BPF, ret, 0)`, so NO grant lookup is compiled into the bpf program (the
`grantable && try_consume_grant(...)` short-circuits on the compile-time-constant 0). NB: the
verified-object diff is at the SOURCE/behavioral level, not byte-for-byte — the split re-codegened
`enforce_bpf` (instruction count shifted), but the disassembly confirms it has ZERO `grant_once`
relocations and ZERO `cmpxchg`, i.e. E0 remains ungrantable. The earlier wording implying binary
invariance was inaccurate.
`enforce_ptrace` calls `enforce_verdict_g(HOOK_PTRACE, ret, 1)`. E3's `enforce_gain` gets the same
splice but only AFTER the `if(!gain) return 0;` check. The broker CLI also rejects
`bpf`/`socket_connect`, but the kernel is the real backstop: even a hand-written `{cg,HOOK_BPF}`
key is never read by any hook, so it is inert.

**The consume sits ONLY on the would-deny path** — after `ret==0`, after the TCB-exempt return,
after `enforce==1`, and for E3 after `gain==1`. So a drop/no-op (E3 `gain==0`), an observe-mode
call (`enforce==0`), and a TCB caller all return BEFORE any consume — a grant is never burned on an
op that would have been allowed anyway. The consume only ever turns this hook's own would-be
`-EPERM` into `0` for one call; it never reverts a prior LSM deny (`if(ret!=0) return ret;` is still
the first statement) and never adds a deny.

**TTL backstop ON (`expire_ns = now + grantTTL`, default 300s).** A stale GRANT over-permits
(fail-DANGEROUS), unlike a stale egress manifest which over-restricts (fail-safe), so the value
carries an `expire_ns` slot checked at consume (`if (v->expire_ns != 0 && now > v->expire_ns)
return 0;`). The broker stamps a real expiry: `bpf_ktime_get_ns` IS `CLOCK_MONOTONIC`, the same
boot-based clock the broker reads via `clock_gettime(CLOCK_MONOTONIC)` on the same host, so a
broker-stamped `expire_ns` is directly comparable to the kernel's consume-time clock (the original
"can't baseline the clock" concern does not hold). An approved-but-unconsumed grant therefore
self-expires in `BULKHEAD_GRANT_TTL` seconds regardless of E0 state — the **E0-independent** recycle
backstop. (On a `clock_gettime` error the broker writes `expire_ns=0` = no TTL, falling back to the
other defenses.)

**Broker gated action `actGrantOnce`**, mirroring `actExpandEgress`. New verb `GRANT-ONCE <hook>`
on the agent-facing broker socket; `cmdGrantOnce` client; `handleGrantOnceTail` peer-attests the
SELF cgroup (SO_PEERPIDFD — the request body carries no identity, so an agent can only grant
ITSELF), validates the hook in `{ptrace,setuid,capset}` (rejects `bpf`/unknown -> `ERR bad-hook`),
optionally short-circuits if the hook is not armed (`OK ... (not-armed, no-op)`), builds
`pending{kind:actGrantOnce, grantHook:<id>}`, and calls `finishGated`. `execute()` takes a new
`grantMu`, `reverifyCgroup`s the attested path, and writes `count=1, expire_ns=now+TTL` via
`ebpf.UpdateAny`. **Count semantics: SET=1, never increment, hard cap 1** — two approvals before a
consume do NOT stack to 2 (no count inflation); a re-grant is idempotent; the kernel CAS only ever
recognizes the value 1, so a corrupted `count!=1` is treated as no-grant (fail-closed). `UpdateAny`
(not `UpdateExist`) because a grant legitimately CREATES the key; the recycle defense is
`reverifyCgroup`, not `UpdateExist`.

**Recycle hygiene / lifecycle (layered, no single point of trust).** (1) The **TTL** (above):
every grant self-expires in `BULKHEAD_GRANT_TTL`s, E0-independent. (2) `reverifyCgroup` in
`execute()` so a grant is only ever WRITTEN against a live-attested cgroup. (3) `ExecStopPost=-+/usr
/bin/bulkhead-collector grant-once clear self` on `bulkhead-agent@.service` deletes all three
`{selfcg,*}` keys on exit (sibling of `egress clear self`; leading `-` so a missing entry never
fails the stop, `+` for CAP_BPF). (4) Collector restart `os.RemoveAll(pinDir)` recreates
`grant_once` EMPTY and resets `enforce_flags` to observe — the only safe state (no grants AND
nothing armed).

**Honest residual-window analysis (found by the ADR-0011 adversarial review).** `grant-once clear
self` (defense 3) runs `bpf()` from the agent's own NON-TCB cgroup, so when **E0/`lsm-bpf` is
armed** the clear is itself EPERM'd and the leading `-` swallows the failure — an unconsumed grant
is NOT cleared on stop. This is the same E0+jail limitation as ADR-0006's `+ExecStartPre egress set
self`, but here the leftover is fail-DANGEROUS (over-permits) rather than fail-safe. It is **not
exploitable** in the current jail launch path, by composition: for a stranded grant to be consumed,
a NEW agent must start at the recycled cgroup id, but under E0-armed that new agent's own
`+ExecStartPre egress set self` `bpf()` is *also* EPERM'd, so it never starts; and the only way to
disarm E0 is a collector restart, which wipes `grant_once`. So `E0 armed ⟹ no recycle consumer`, and
`disarm ⟹ wipe`. Defense (1), the **TTL, closes it regardless**: a stranded grant expires in
≤`grantTTL` even if E0 is armed and the composition argument is ever weakened (e.g. a future agent
type that starts without a `bpf()`-ing `ExecStartPre`). So `ExecStopPost` clear-self is a prompt
best-effort reclaim, NOT the authoritative backstop — the TTL is. The cleaner future fix (a
TCB-context clear: the broker deletes `{cg,*}` on observed agent exit) is named in the seam.

**Invariants preserved (unchanged):** no self-approval (uid-0 0600 `approve.sock` + SO_PEERCRED
uid==0; agents are non-root DynamicUser); execute() reached only after `<-decision == true`; ONE
signed decision recorded AFTER execute (so the chain reflects the actually-written grant).

## Verification

Host `go test -race`: `TestGrantOnceConsumeArithmetic` (a Go `atomic.CompareAndSwapUint32` model of
the CAS: exactly one of K concurrent consumers wins from count=1, zero from count=0, never negative),
`TestGrantKeyPerHookDistinct` (the encoded `grantKey{cg,setuid}` != `{cg,ptrace}` != `{cg2,setuid}`
byte-for-byte — proves cross-hook and cross-cgroup isolation at the key level),
`TestGrantHookRejectsNonGrantable` (the handler validator rejects `bpf`/`socket_connect`/unknown,
accepts ptrace/setuid/capset), `TestGateActionAgnostic`-style for `actGrantOnce`.

qemu (probe-based, NO setpriv/su; E1+E3 armed FIRST so the before-probe is genuinely denied):
1. **baseline-deny** — armed, no grant: `probe setuid` exits 1, `probe capset` exits 1, `probe
   ptrace` exits 1. The floor bites.
2. **grant+consume (headline exactly-once)** — agent `grant-once setuid`; operator `approve allow
   <id>`; broker writes count=1. Next `probe setuid` exits 0 (the single allow); an IMMEDIATE second
   `probe setuid` exits 1 again (consumed exactly once). Repeat for capset and ptrace.
3. **cross-hook isolation** — after `grant-once setuid` approved+consumed, `probe capset` still
   exits 1 (the setuid key does not satisfy a capset consume).
4. **deny/timeout** — `approve deny` / no action -> `ERR deny`/`ERR timeout`, grant map unchanged,
   probe still exits 1.
5. **E0 not grantable** — `grant-once bpf` -> `ERR bad-hook`; and a hand-poked
   `grant_once[{cg,HOOK_BPF}]=1` leaves `enforce_bpf` denying (no consume path on E0).
6. **concurrency** — `probe setuid --race N` spawns N threads racing the regain after ONE grant;
   assert exactly one exits 0.
7. **recycle** — `grant-once`+approve (unconsumed), `systemctl stop` the agent -> `ExecStopPost`
   clears it (with E0 OFF) -> `status` shows no grant. NB: with E0 ARMED the clear is EPERM'd (see
   the residual analysis); the TTL is the backstop there.
8. **restart wipe** — grant+approve, `systemctl restart bulkhead-collector` -> `status` shows zero
   grants + observe; grant gone.
9. **TTL backstop** — with a low `BULKHEAD_GRANT_TTL`, `grant-once`+approve then DELAY past the TTL
   before consuming -> the post-grant probe is DENIED (the grant self-expired), E0-independent.
Plus: the broker signed chain has a `grant-once` decision record (verify-audit passes) and the
collector provenance chain shows the consume as decision=allowed mode=enforce.

**As verified (`/tmp/granttest.py`, ALL PASS):** the LOAD gate (object loads => verifier accepts
`BPF_CMPXCHG` on 6.6.127), E1 ptrace armed, baseline-deny, grant+consume-exactly-once (arms 1/2),
deny-no-grant (arm 4), agent-gating (a console `grant-once` is refused — non-agent cgroup), the
signed record + verify-audit, the empty-after-consume map, and the TTL backstop (arm 9). The live
demo op is **ptrace** because it needs no caps and keeps the agent non-root (so it provably cannot
self-approve); E3's consume is the IDENTICAL `try_consume_grant` call spliced into `enforce_gain`,
covered by the host CAS test + the bytecode disassembly (the adversarial review confirmed
`enforce_setuid`/`enforce_capset` each carry exactly one `BPF_CMPXCHG` + `grant_once` lookup/delete,
and `enforce_bpf` carries none).

A new `bulkhead-collector probe ptrace` is added (self-contained: parent PTRACE_ATTACHes a child it
spawned in the same cgroup; exit 1 on EPERM, 0 on attach). The E1 probe must ensure the BPF hook —
not host-wide Yama ptrace_scope — is the thing under test.

bpf2go regen (the load-bearing step; first map+program-shape change since E3): regenerate
`bpf_bpfel.o` + `bpf_bpfel.go` with `bpf2go -target bpfel -type event` for go1.22. bpf2go
auto-emits Go mirrors `bpfGrantKey`/`bpfGrantVal` for the struct map key/value (no hand-declaring),
and the generated `bpfMapSpecs`/`bpfMaps` gain a `GrantOnce` field. Confirm the object
LOADS in qemu (the verifier accepts the `BPF_CMPXCHG` on the 64-bit `grant_once` map value) BEFORE relying on any
arm — a verifier rejection is the top risk and must be caught at load. Diff the disassembly so the
only delta vs the E3 object is the `grant_once` map + the consume insns, and re-run the E0-E3
regression. Bump the bulkhead-collector recipe SRCREV to the commit carrying the regenerated object.

## Seam left clean

The TTL is ACTIVE (the broker stamps `expire_ns = CLOCK_MONOTONIC now + grantTTL`). The cleanest
remaining hardening — flagged by the adversarial review — is a **TCB-context clear**: have the
broker (already TCB-registered, so its `bpf()` survives E0) delete an agent's `{cg,*}` grant keys
when it observes the cgroup exit, so cleanup no longer depends on the agent's own (E0-blockable)
`bpf()`. Until then the TTL is the E0-independent backstop. Other deferred: a per-agent grant
ceiling map, a dedicated broker record type (deferred since ADR-0007 instead of overloading
`provEvent`), persistent grants across restart (deliberately NOT done — restart-wipe is the
fail-safe). No new systemd unit; the agent template gains two `ExecStopPost` lines (egress + grant
clear).