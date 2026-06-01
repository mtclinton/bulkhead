# ADR 0004 — BPF-LSM enforce mode (observe → enforce)

- **Status:** Accepted
- **Date:** 2026-05-31
- Follows [ADR 0001](0001-foundational-architecture.md) (decision #8: "a BPF-LSM
  deny layer comes later") and [ADR 0003](0003-yocto-production-migration.md)
  (Yocto 6.6 migration).

## Context

The floor — nftables default-deny egress, a seccomp syscall allowlist, Landlock
filesystem confinement, dropped capabilities, and ns/cgroup jails — is a strong
*perimeter and resource* cage, but every layer is either per-*service* (the
seccomp/Landlock profile is baked at launch) or per-*host* (one nftables ruleset,
one LSM config). Nothing keys a decision on **which agent is acting at the moment of
the action**. That keyed decision is the project's thesis: agent action
authorization as an OS primitive. `bpf_get_current_cgroup_id()` inside an LSM hook is
the only generic mechanism that delivers it at action time.

The collector already attaches an observe-only `lsm/socket_connect` program
(`src/collector/provenance.bpf.c`) that always `return ret;`. This ADR promotes the
BPF-LSM collector from observe-only to **optionally** enforcing, advancing per-agent
action authorization **without duplicating** the floor.

Authoritative kernel facts (verified on the build, kernel **6.6.127**):

- `CONFIG_BPF_LSM=y`, `CONFIG_LSM="landlock,lockdown,yama,bpf"`, cmdline
  `lsm=landlock,lockdown,yama,bpf` — **bpf is ordered LAST**, the safety keystone.
- A `BPF_PROG_TYPE_LSM` program's return value *is* the verdict: `0` = allow, a
  negative errno (`-EPERM`) = deny. It receives the running verdict as its last `int
  ret` arg. The LSM dispatcher short-circuits on the first deny, so a bpf-last program
  sees `ret==0` for anything the floor already allowed and can only **add** a denial —
  it can never revert a prior in-tree deny.
- **No verifier return-value guardrail on 6.6.127.** The range-check series
  (`LSM_RET_INT`, `bpf_lsm_get_retval_range`, the disabled-hooks list) landed ~6.11
  and is absent here. So the verifier will *not* reject `-EPERM` on a hook the kernel
  cannot safely deny. We self-impose the discipline: only return deny from hooks
  declared `LSM_HOOK(int, 0, ...)` in `lsm_hook_defs.h` (e.g. `bpf`,
  `ptrace_access_check`, `task_fix_setuid`, `capset`, `socket_connect`); never from
  `{0,1}`/void-default hooks (`cred_prepare`, `task_alloc`). This is a code-review
  checklist item *and* a self-test assertion.

## Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | **Enforce is opt-in, default-OBSERVE.** A per-hook enforce-toggle BPF array map defaults to 0 (off). The shipped image boots in observe mode exactly as today. | The deny layer must never be the *only* enforcement; the floor stays authoritative. |
| 2 | **Fail-OPEN everywhere.** Map-miss, lookup error, ringbuf-full, unresolved cgroup id, or toggle-off all degrade to `return ret` (allow). BPF never default-denies. | A logic bug, empty map, or crashed loader degrades to *today's behavior*, never to a bricked appliance. |
| 3 | **First enforce target: `lsm/bpf`** — deny `bpf()` from agent cgroups; allowlist the collector's and init's cgroups. | Highest unique value (seccomp can't be cgroup-aware: the collector needs `bpf()`, agents never do), off every boot/service path, and it protects the BPF substrate the whole TCB rests on. A bug fails into "agents can't load BPF" — the desired state. |
| 4 | **Per-hook enforce flags; monotonic rollout.** Each enforceable hook has its own slot in the toggle map; ship `lsm/bpf` enforce alone, keep `socket_connect` and all others observe-only. | The rollout is monotonic and reversible per hook; observe-then-enforce ("would-deny" logging) precedes flipping any hook live. |
| 5 | **Userspace kill-switch, no reboot.** `bulkhead-collector enforce off` clears the toggle map (instant soft-off); `bulkhead-collector disarm` closes the LSM link (full detach). | Operators can disarm without a reboot; combined with fail-open, this is the lockout escape hatch. |
| 6 | **Keep the Ed25519 hash-chained provenance log; now record allow/deny decisions.** Every hook decision (allowed or denied, observe OR enforce) is appended to the signed log with `decision` and `mode` fields. | Provenance stays complete; "would-deny" observations are auditable before enforcement is flipped on. |
| 7 | **Self-test gate extended, fail-CLOSED — but the gate itself is never blocked by enforce.** The enforce self-test asserts: from an agent-equivalent cgroup `bpf(BPF_MAP_CREATE)` returns EPERM (when armed) AND from the collector cgroup it still succeeds. Enforce is armed only *after* the boot self-test + networking are up; on any assertion failure it disarms (fail-open). | Enforce must never block the boot/networking/RAUC/selftest paths; the selftest proves enforce works before it becomes authoritative. |

## How it LAYERS with the floor (does not duplicate)

- **`lsm/bpf`**: nftables/Landlock don't touch it; seccomp can block `bpf(2)`
  per-service but cannot say "collector may, agents may not" (the collector needs it).
  BPF-LSM keyed on cgroup is the *only* place this rule is expressible. New capability,
  no overlap.
- **`socket_connect` (deferred)**: nftables default-deny egress is host-wide and
  authoritative; BPF egress only adds value once *per-agent* policy lands. Until then
  it stays observe-only so we don't duplicate the floor.
- **module/firmware load**: lockdown LSM + the module-less image already floor this
  host-wide; marginal value is per-agent attempt-logging only → observe-only.

## Fail-safe posture

Default observe; enforce is opt-in and fail-OPEN. The one-way ratchet
(`if (ret) return ret;` as the first statement) guarantees BPF can only make the system
stricter, never punch a hole in an in-tree LSM deny. Every uncertain code path returns
the incoming `ret`. The toggle map default-0 plus the link-detach kill-switch mean the
appliance can always be returned to the known-good observe-only behavior with a single
map write or link close — no reboot.

## Consequences

- Threat-model non-goal updated: BPF-LSM is observe-only by default; `lsm/bpf` enforce
  is available opt-in as of this increment (E0).
- architecture.md enforcement section: the provenance fabric gains an optional,
  fail-open deny capability gated on a per-hook toggle.
- Code-review checklist gains the 6.6.127 rule: deny only from `LSM_HOOK(int, 0, ...)`.
- The bpf2go object is regenerated and re-committed (CGO off, vendored cilium/ebpf
  v0.17.3).

## Roadmap (per-hook, each behind its own flag)

- **E0 (this ADR):** `lsm/bpf` enforce, opt-in. **DONE.**
- **E1:** `lsm/ptrace_access_check` (agents may not ptrace). **DONE.**
- **E2:** `lsm/socket_connect` per-agent egress (agent → declared destinations),
  driven by the capability manifest. **DONE** (see below).
- **E3:** `lsm/task_fix_setuid` + `lsm/capset` — deny privilege *gains* (allow drops).
  **DONE** (see below). This completes the enforce roadmap.

## E3 realization — deny privilege *gains*, always allow drops

Two hooks, each with its own flag (`setuid`, `capset`), sharing an `enforce_gain()`
gate that is the fail-open `enforce_verdict()` plus one extra precondition: the
transition must *raise* privilege. Drops and no-ops are always allowed — so a jailed
agent can still `setuid`/`capset` *downward* (the common, safe direction), but cannot
climb back.

- **`task_fix_setuid`**: gain ⇔ `new.euid == 0 && old.euid != 0` (regaining effective
  root). The classic case: a process that dropped to a non-root euid while retaining
  `suid == 0` — the kernel *permits* it to return to euid 0, so the BPF hook adds the
  denial the kernel would not make.
- **`capset`**: gain ⇔ the requested effective or permitted set contains a bit the old
  cred lacked (`(new & ~old) != 0`). Raising *effective* within an already-held
  *permitted* set is kernel-permitted; the hook denies it for non-TCB cgroups.
  `kernel_cap_t` is a single `u64` on 6.6.
- Both are `LSM_HOOK(int, 0, ...)` → deny-safe on 6.6.127. Reads use
  `bpf_probe_read_kernel` against fixed offsets from the pinned kernel's `vmlinux.h`.
- Verified with a self-contained probe (`bulkhead-collector probe setuid|capset`, no
  dependency on `setpriv`/`su` in the image): run as root from a non-TCB cgroup, it
  drops privilege (allowed) then regains it (denied iff armed) and exits 1 on denial.
- Same default-observe / soft-kill-switch / TCB-exempt semantics as E0–E2.

## E2 realization — destination *classes*, not named hosts

"Declared destinations" could mean a per-agent list of allowed hostnames/IPs. We
deliberately did **not** build that, because it would duplicate the authoritative
dnsmasq→nftset dynamic allowlist (which already resolves names to IPs at the network
layer, host-wide). Instead the per-agent manifest is a bitmask of destination
**classes** — `loopback`, `linklocal`, `private` (RFC1918 + `100.64/10` CGNAT/tailnet
+ IPv6 ULA), `public`, `other` (non-INET: unix/netlink local IPC) — classified
in-kernel purely from the connect `sockaddr`. So there is **no IP set to keep in
sync**, and the two layers *compose*: BPF decides *whether* an agent may attempt
public egress at all; nftables still constrains *which* public IPs it may reach.

- Map `egress_policy` (HASH `cgroup_id`→`u32` mask). **Absent ⇒ no manifest ⇒
  unrestricted** (fail-open; the floor still applies). Present ⇒ a connect whose
  class is absent from the mask is a deny candidate.
- Same fail-open gate as E0/E1: deny (`-EPERM`) requires `ret==0` AND cgroup∉TCB AND
  manifest-present-and-class-not-allowed AND `enforce_flags[socket_connect]==1`. TCB
  and prior-LSM-deny are always honored. `socket_connect` is `LSM_HOOK(int,0,...)`.
- The single `prov_socket_connect` program does both jobs: it still logs **every**
  connect (full provenance) and now also computes/applies the verdict — no second
  program on the hook.
- CLI: `bulkhead-collector egress set|clear <self|id:N|cgroup-path> <classes>`;
  `enforce on socket_connect` arms it; `status` lists manifests. Map pinned at
  `/sys/fs/bpf/bulkhead/egress_policy`.
- **Caveat:** because `socket_connect` also fires for AF_UNIX/AF_NETLINK, a manifest
  that omits `other` will deny local IPC for that cgroup once armed. Manifests for
  agents that need local sockets must include `other` (and usually `loopback`).
- **Note:** the manifest keys on cgroup id. Per-agent cgroups are now realized by the
  agent jail runner (ADR-0005, `bulkhead-agent@.service`), so E1/E2/E3 are genuinely
  per-agent; E2 was first verified against a non-TCB login-session cgroup and is now
  also driven through two real per-agent jails (ADR-0005's A-vs-B demo).
