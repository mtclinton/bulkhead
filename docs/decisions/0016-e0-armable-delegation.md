# ADR-0016: E0-armable delegation — the collector as sole bpf() write chokepoint

Status: Accepted
Date: 2026-06-03
Relates to: ADR-0004 (E0–E3 enforce + the TCB model), ADR-0005 (agent jail runner; the
+ExecStartPre happens-before), ADR-0006 (inter-agent egress delegation; the named "E0 + delegation"
limitation), ADR-0011 (one-shot grant), ADR-0012 (TCB-context GC), ADR-0013 (composed-system
hardening; reconcileTCB / lock-order invariants). Closes ADR-0006 lines 75–82 ("Limitation:
E0 + delegation") and ADR-0005 lines 95–102 ("E0 + E2 together — the one real limitation").

## Context

The flagship claim — "agents are PHYSICALLY unable to bpf() because E0 is kernel-enforced" — is
today only true in a configuration where delegation is BROKEN. Confirmed in source:

- `brokerSelfRegisterTCB` (broker.go:217–228) writes `tcb_cgroups` via `bpf()` from `system.slice`
  while the broker is NOT yet TCB; the unit comment itself admits "self-registration needs E0 OFF
  at first run" and the call `log.Fatalf`s on EPERM (broker.go:147–149).
- The agent template's `+ExecStartPre=… egress set self` (bulkhead-agent@.service) runs
  `cmdEgress` (main.go:283–316), a DIRECT `egress_policy.Update` from the CHILD's own NON-TCB
  cgroup — EPERM'd under E0. (Plus the `grant-once clear self` / `egress clear self`
  ExecStartPre/ExecStopPost hygiene verbs.)
- `bulkhead-broker.socket` is auto-enabled with `After/Requires=collector` but NO ordering vs
  `bulkhead-enforce.service`; `bulkhead-enforce.service` is NOT auto-enabled and NO qemu script
  arms `enforce on bpf` (only E2 / `enforce on socket_connect`). So in a hardened prod config the
  broker's first socket activation would EPERM its self-register and die; delegation/EXPAND/
  grant-once only work when E0 is OFF — i.e. when the bpf substrate is unprotected.

The broker's EXPAND (broker.go:401–428), NARROW (narrow.go:148–199) and GRANT-ONCE
(grant.go:111–131) writes already run INSIDE the broker process, so they are E0-legal the instant
the broker cgroup is genuinely TCB. The fix is therefore NOT "move every write" — it is "remove the
two writes that happen from a non-TCB cgroup," and establish broker-TCB from the already-TCB
collector. This is ADR-0006's pre-specified direction (lines 79–82).

## Decision

The COLLECTOR — already TCB, E0-exempt, the single map owner that `RemoveAll`/re-pins each run — is
the SOLE issuer of every `bpf()` WRITE on behalf of a non-collector caller, via one authenticated
control socket. The broker becomes TCB by collector-granted membership and keeps its own reviewed
RMW/read code unchanged.

1. **Control IPC.** `runCollector` opens `/run/bulkhead/control.sock` (0660 root:root, via the
   existing `RuntimeDirectory=bulkhead`) AFTER pinning the maps + seeding TCB and BEFORE the
   ringbuf loop — so it exists before E0 can arm. Line protocol mirroring the broker's OK/ERR,
   goroutine-per-conn, 5s deadline. Verbs: `EGRESS-SET-SELF <classes>`, `EGRESS-CLEAR-SELF`,
   `GRANT-CLEAR-SELF`, `TCB-REGISTER-BROKER`, `WAIT-BROKER-TCB`. Every connection is authenticated
   from the kernel — `SO_PEERCRED` (uid==0) AND `SO_PEERPIDFD` (pidfd-pinned pid → `/proc/<pid>/
   cgroup` path + inode cgid, the exact pin-against-recycle pattern already in `peerParentCgID`) —
   NEVER from the request body.

2. **The two non-TCB writes are eliminated.** `brokerSelfRegisterTCB` is DELETED; the broker no
   longer self-`bpf()`s. The agent template's `egress set self` / `egress clear self` /
   `grant-once clear self` become thin control-IPC clients (`bulkhead-collector ctl …`) that ask
   the collector to do the `bpf()` from its TCB context. The collector derives the target cgid
   ITSELF from the connecting `+ExecStartPre` process's attested cgroup (the same instance cgroup
   the payload runs under), requires that path to be under `/bulkhead-agent.slice/bulkhead-agent@`,
   and writes only `egress_policy`/`grant_once` for that SELF cgid — never `tcb_cgroups`, never
   another cgroup.

3. **EXPAND/NARROW/GRANT-ONCE and the broker's read Lookups DO NOT MOVE.** They keep their
   `egressMu`/`grantMu` locking and `reverifyCgroup` live-rebind (the ADR-0013 F1/F3/F6/F7 fixes)
   and become E0-legal once the broker cgroup is TCB. The thesis sentence is "no NON-TCB cgroup
   issues `bpf()`"; the broker IS TCB by collector grant, so it is not a counterexample. This is
   the minimal diff — it does not re-plumb the most-reviewed code through a cross-process IPC.

4. **Broker TCB membership is collector-established, three agreeing ways** (all stat the SAME fixed
   `brokerCgroupPath = /sys/fs/cgroup/system.slice/bulkhead-broker.service`): (a) at pin time in
   `runCollector`, register the broker cgid if its dir exists; (b) a synchronous
   `TCB-REGISTER-BROKER` the broker sends at startup, BLOCKING (log.Fatal on failure) before it
   listens, for socket-(re)activation-after-pin; (c) `reconcileTCB` becomes
   reconcile-to-{root,collector,live-broker} — it ADDS the live broker cgid if absent (resolved
   ONLY from `brokerCgroupPath`) as the ≤GC-interval backstop. **Anti-arbitrary-register guard:**
   `TCB-REGISTER-BROKER` takes NO target argument; the collector requires the attested caller path
   to be string-EQUAL (`filepath.Clean`, not substring/prefix — no nested/sibling cgroup passes)
   to the fixed `brokerCgroupPath`, then re-stats THAT exact path itself to derive the cgid. The
   only `tcb_cgroups` Updates are `runCollector`'s seed and `reconcileTCB` — both collector-
   internal, both keyed on collector-resolved paths.

5. **E0 is now ARMABLE end-to-end; it stays OPT-IN.** `bulkhead-enforce.service` is reordered
   `After=bulkhead-collector.service bulkhead-broker.service`, `Wants=bulkhead-broker.service`,
   with `ExecStartPre=… ctl wait-broker-tcb` (blocks until the collector confirms the broker cgid
   is registered, so E0 never arms ahead of broker-TCB establishment). `bulkhead-broker.service`
   gains `Before=bulkhead-enforce.service` so PID-1 materializes the broker cgroup + the broker
   self-registers before E0 arms; `PartOf=collector` stays. Agents gain
   `After=bulkhead-enforce.service` so no payload forks before E0 is armed when enforce is in the
   transaction. We deliberately did NOT auto-enable `bulkhead-enforce.service`: the shipped image
   keeps ADR-0004's default-OBSERVE posture (operational safety — an unexpected boot-path `bpf()`
   cannot brick the box), and an operator opts into the full hardened posture with
   `systemctl enable --now bulkhead-enforce.service`, which now WORKS (delegation/EXPAND/grant-once
   all keep working under E0). Flipping the shipped default to E0-armed is a one-line recipe change
   (add it to `SYSTEMD_SERVICE`), left as an explicit posture decision (see Seam). Opt-in/first-boot
   stays fail-open-to-observe (`enforce_flags` empty ⇒ observe by construction); a collector restart
   `RemoveAll` resets E0 to observe AND re-seeds the broker before re-pin, so a crash can never
   strand E0-armed against a non-TCB broker.

6. **Review hardening** (an adversarial pass confirmed C2 no-arbitrary-TCB-register, C3 self-cgid +
   happens-before, and the broker-register auth all HOLD — no escalation — and surfaced three
   operability/precision items, all fixed here): (a) the soft-disarm was broken — `enforce off bpf`
   issued a `bpf()` from a non-TCB cgroup that E0 EPERMs, so the documented kill-switch silently
   failed while systemd reported the unit stopped. `cmdEnforce` now ROUTES through the collector
   (a uid-0, non-agent-gated `ENFORCE-SET` control verb), so arm AND disarm work under E0. (b)
   `bulkhead-enforce.service` / `-egress.service` gain `PartOf=bulkhead-collector.service` so a
   collector restart (which `RemoveAll`-resets `enforce_flags` to observe) re-runs the arm against
   the fresh map instead of silently dropping to observe while reporting armed. (c) the agent-cgroup
   gate (the self-verb gate AND the broker delegation gate) moves from `strings.Contains` to an
   anchored structural match (`isAgentCgroup`), so a crafted uid-0 cgroup path that merely embeds
   the marker (a nested sub-scope, a marker-named slice elsewhere) no longer passes — bounded
   defense-in-depth, since self-verbs only ever narrow the attested-self cgid.

No new BPF program or map: the verified E0–E3 object is byte-for-byte unchanged; the only state
E0-arming sets is `enforce_flags[HOOK_BPF]=1`. All changes are pure-Go (`control.go`, `main.go`
wiring, the `broker.go` deletion, `gc.go`) + systemd units + the Yocto SRCREV bump.

## Verification

Host `go test` (src/collector) covers the kernel-free AUTHORIZATION guards — the security-critical
logic: `TestIsAgentCgroup` (a self-verb / broker-delegation caller is honored only for an anchored
agent-INSTANCE leaf — the collector, the broker, an operator login, the bare slice, AND crafted
embedded-marker paths like a nested sub-scope or a marker-named slice under the wrong parent are all
rejected) and `TestIsBrokerCaller` (the anti-arbitrary-register guard — only the string-equal broker
cgroup passes; sibling / nested / substring-prefix / `..`-traversal / missing-leading-slash all
rejected, so no caller can drive a TCB registration of another cgroup). The map-write + live
`SO_PEERPIDFD` attestation paths require a kernel + the pinned BPF maps and are exercised by the
qemu arm below. All ADR-0012/0013 suites stay green unchanged (the EXPAND/NARROW/GRANT RMW +
`reverifyCgroup` + lock code is untouched).

The E0-ARMED qemu arm (`scripts/qemu-e0-check.py`, `make verify-e0`) — the artifact that converts
the thesis from aspirational to demonstrated, with E0 armed the whole time:
- **broker TCB-by-grant**: `ctl wait-broker-tcb` confirms the broker is in tcb_cgroups via the
  collector control socket (not a self-`bpf()`).
- **E0-DENY (before/after on the SAME command)**: a direct `bpf()` map write from the console's
  non-TCB cgroup (`egress set self`) SUCCEEDS in observe, then is EPERM'd once E0 is armed —
  agents are physically unable to `bpf()`.
- **DELEGATE-UNDER-E0**: a mock-driven parent (loopback,other; NO public) delegates a child
  requesting public,…; the child's manifest is written `loopback,other` (public AND-cleared) via
  the collector control RPC under E0, its public fetch is E2-DENIED under its own cgid, it FINALs,
  and the broker signs the delegate record (gen + task_sha) from its TCB context — proving the
  broker's TCB-context writes AND the child's control-socket manifest write both work with the bpf
  substrate sealed.
- **SOFT-DISARM**: `systemctl stop bulkhead-enforce` (routed `enforce off bpf`) actually disarms E0
  under E0 — the same console direct `bpf()` succeeds again afterward (the review-fixed kill-switch).
- **AUDIT**: both signed chains verify after the run.
The BEFORE baseline (the current-tree FAIL: broker self-register EPERM/log.Fatal; child
+ExecStartPre EPERM) is code-verified and documented; the harness asserts the AFTER state.

## Seam

DEFERRED (noted, not built): folding the broker's EXPAND/NARROW/GRANT RMW + read Lookups onto the
control socket for a literal "ONLY the collector ever `bpf()`s" invariant (the broker is TCB by
collector grant, so the current scope is sufficient and the larger change would re-plumb the
ADR-0013-hardened RMW/lock code); deriving the expected broker cgroup path from the unit name at
build time (today a single shared `brokerCgroupPath` constant + a unit-file lint asserting no
`Slice=` on the broker); an instant (vs ≤GC-interval) agent-in-TCB reconcile guard; auditing the
collector's own control-socket writes into a signed chain (today only the broker's gated decisions
and the kernel verdicts are signed).