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
`enforce_bpf` calls `enforce_verdict(HOOK_BPF, ret)` (unchanged) which forwards
`enforce_verdict_g(HOOK_BPF, ret, 0)` — so NO grant lookup is compiled into the bpf program.
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

**TTL field present, default-OFF (`expire_ns==0` = no expiry).** A stale GRANT over-permits
(fail-DANGEROUS), unlike a stale egress manifest which over-restricts (fail-safe), so the value
carries an `expire_ns` slot checked at consume (`if (v->expire_ns != 0 && now > v->expire_ns)
return 0;`). v1 writes `expire_ns=0` (no TTL): the broker cannot trivially read the kernel's
`bpf_ktime` monotonic baseline to stamp a correct expiry, and `ExecStopPost` clear-self is the
authoritative cleanup. Baking the field in now means a future TTL is a value-WRITE change, not an
ABI/layout break to the verified object. Primary recycle hygiene is the agent's `ExecStopPost`
clearing its grants + `reverifyCgroup` at write.

**Broker gated action `actGrantOnce`**, mirroring `actExpandEgress`. New verb `GRANT-ONCE <hook>`
on the agent-facing broker socket; `cmdGrantOnce` client; `handleGrantOnceTail` peer-attests the
SELF cgroup (SO_PEERPIDFD — the request body carries no identity, so an agent can only grant
ITSELF), validates the hook in `{ptrace,setuid,capset}` (rejects `bpf`/unknown -> `ERR bad-hook`),
optionally short-circuits if the hook is not armed (`OK ... (not-armed, no-op)`), builds
`pending{kind:actGrantOnce, grantHook:<id>}`, and calls `finishGated`. `execute()` takes a new
`grantMu`, `reverifyCgroup`s the attested path, and writes `count=1, expire_ns=0` via
`ebpf.UpdateAny`. **Count semantics: SET=1, never increment, hard cap 1** — two approvals before a
consume do NOT stack to 2 (no count inflation); a re-grant is idempotent; the kernel CAS only ever
recognizes the value 1, so a corrupted `count!=1` is treated as no-grant (fail-closed). `UpdateAny`
(not `UpdateExist`) because a grant legitimately CREATES the key; the recycle defense is
`reverifyCgroup`, not `UpdateExist`.

**Recycle hygiene / lifecycle.** (1) `ExecStopPost=-+/usr/bin/bulkhead-collector grant-once clear
self` on `bulkhead-agent@.service` deletes all three `{selfcg,*}` keys on exit (sibling of `egress
clear self`; leading `-` so a missing entry/down collector never fails the stop, `+` for CAP_BPF).
(2) `reverifyCgroup` in `execute()` so a grant is only ever WRITTEN against a live-attested cgroup.
(3) Collector restart `os.RemoveAll(pinDir)` recreates `grant_once` EMPTY and resets `enforce_flags`
to observe — the only safe state (no grants AND nothing armed). Residual window: only if a grant is
unconsumed AND `ExecStopPost` is skipped (collector down at stop) AND the EXACT cgroup inode id is
recycled onto a new armed agent that itself performs the same op — then it spends ONE op (a single,
audited leak, not an escalation). The TTL field is the deferred backstop for this.

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
7. **recycle** — `grant-once setuid`+approve (unconsumed), `systemctl stop` the agent ->
   `ExecStopPost` clears it -> `status` shows no grant; restart (new cgid) -> `probe setuid` exits 1.
8. **restart wipe** — grant+approve, `systemctl restart bulkhead-collector` -> `status` shows zero
   grants + observe; grant gone.
Plus: the broker signed chain has a `grant-once` decision record (verify-audit passes) and the
collector provenance chain shows the consume as decision=allowed mode=enforce.

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

The TTL is value-WRITE-ready (the `expire_ns` field exists; v1 writes 0). Future increments: a
broker-stamped `bpf_ktime`-baselined TTL, a per-agent grant ceiling map, a dedicated broker record
type (deferred since ADR-0007 instead of overloading `provEvent`), persistent grants across restart
(deliberately NOT done — restart-wipe is the fail-safe). No new systemd unit; the agent template
gains one `ExecStopPost` line.