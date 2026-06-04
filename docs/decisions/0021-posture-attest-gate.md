# ADR-0021: Posture self-attest gate — making attestation load-bearing

Status: Accepted
Date: 2026-06-04
Relates to: ADR-0004 (E0–E3 enforce), ADR-0016 (the control socket), ADR-0018 (harden-by-default —
boots E0+E2 armed, fail-SAFE to observe), ADR-0019/0020 (remote attestation, now EK-rooted).

## Context

After ADR-0019/0020 the box can PROVE its enforcing posture to an off-box relying party (a fresh-nonce
EK-rooted-AK quote). But that proof is still purely *advisory*: nothing on the box FAILS CLOSED when
the posture is wrong. A soft-disarmed (`systemctl stop bulkhead-enforce`), failed-to-arm, or
TCB-strangered box happily brings up the tailnet and serves agents with the egress floor down. This
ADR makes attestation LOAD-BEARING — the non-cryptographic half: a real action (the tailnet join)
fail-closes unless the box is in the expected enforcing posture.

It is deliberately the *non-cryptographic* half. The full cryptographic self-verify (a local
fresh-nonce → EK-rooted quote → off-box `attest verify` against a build-derived expected-D) is blocked
by a reproducible-expected-D prerequisite (the verifier today sources D from the box's own journal) and
is the explicit follow-up. This slice ships the part that needs no quote, no D, no TPM — and delivers
the headline operational property today.

## Decision

1. **The predicate** (`gatePosture()`, in the collector/TCB): `E0 armed AND E2 armed AND tcb_cgroups
   clean`, read LIVE from the SAME pinned maps `attestDigest()` reads — one source of truth, no new
   map-read code. A `Lookup` miss ⇒ 0 ⇒ observe (mirrors `attestDigest`), so an empty/RemoveAll-reset
   `enforce_flags` reads as NOT armed and FAILS CLOSED; a map-OPEN error returns an error ⇒ the CLI
   exits non-zero ⇒ fail-closed, never silently "assume armed". It requires EXACTLY the ADR-0018
   default-armed set `{E0,E2}`: requiring E1/E3 (never armed by default) would fail every healthy boot;
   requiring less would let an E2-dropped-to-observe box (egress floor down — the posture tailnet
   exposure most cares about) still join. A stranger in `tcb_cgroups` is an E0-exempt escape hatch, so
   "armed but dirty TCB" must NOT pass.

2. **In the collector via a new `ATTEST-GATE` control verb.** The `enforce_flags`/`tcb_cgroups` reads
   are `bpf()` syscalls a non-TCB unit's cgroup CANNOT issue under armed-E0 (EPERM) — which is exactly
   what gives the gate teeth: the read itself is privileged/uncircumventable, and the maps the gate
   reads ARE the maps the BPF-LSM programs consult on every syscall (same pin path), so "the gate says
   E0 armed" and "the kernel actually denies bpf() for non-TCB" are the same bit. `attest gate` is a
   thin client; the collector (TCB) evaluates the predicate, operator-gated (uid-0 + non-agent) like
   `ATTEST-EXTEND`. The client uses a new `controlRPCGate` that retries ONLY on a TRANSPORT failure
   (the boot-race window before the collector binds the socket) and returns a server `ERR not-armed`
   IMMEDIATELY — so a disarmed box fail-closes fast instead of hanging the 30s race window.

3. **Wired as a fail-closed dependency** of `tailscale-up.service`: a new `bulkhead-attest-gate.service`
   oneshot ExecStarts `attest gate` (exit 0 = armed), and `tailscale-up` `Requires=`+`After=` it plus a
   belt-and-suspenders `ExecStartPre=/usr/bin/bulkhead-collector attest gate` (closes the manual
   `systemctl start` seam where systemd may re-pull a failed `Requires`). The gate unit conditions on
   the COLLECTOR BINARY (`ConditionPathExists=/usr/bin/bulkhead-collector`) — NOT `/dev/tpmrm0` (the
   gate reads BPF maps, not the TPM; a TPM-less armed box must still be gated) and NOT the control
   socket (the collector is `Type=exec`, so it goes active before binding the socket — a socket
   Condition would race-skip the gate and silently fail-OPEN; `controlRPCGate`'s retry absorbs that race
   instead). `PartOf=bulkhead-collector.service` re-evaluates the gate after a collector restart
   (RemoveAll-reset + re-arm), so a stale "active" gate can't outlive a re-arm.

**Polarity** is deliberately OPPOSITE ADR-0018's fail-safe: this BLOCKS the tailnet on observe.
Blocking is NOT a brick — only the JOIN is gated; the serial/local console always survives.
**Break-glass** is documented in `deploy/tailscale-join.md`: the supported recovery is to RE-ARM; a
deliberate persistent observe-mode downgrade requires EDITING the base unit to drop the hard
`Requires=` (masking the gate does NOT work — a masked `Requires=` is a hard `is masked` failure that
refuses the join, not a vacuous satisfaction, so masking would brick the rejoin). Continuous runtime teardown (BindsTo/timer killing an established tailnet
on a later disarm) is deliberately OUT of scope: this is boot/restart-time fail-closed, not a live
kill-switch.

## Verification

Host `go build`/`vet`/`test` (offline `-mod=vendor` recipe build). QEMU (`scripts/qemu-attest-check.py`
+ `make verify-attest`, swtpm): the existing 17 ADR-0019/0020 checks are a regression guard and stay
green; appended — POSITIVE: the gate unit is ACTIVE from cold boot (proves the binary-Condition +
`controlRPCGate` retry beat the socket race, and the `{E0,E2}` predicate doesn't self-brick a healthy
boot) and `attest gate` returns `OK e0=1 e2=1 tcb_clean=true`; WIRING: `tailscale-up` `Requires=` the
gate (static load-bearing edge; the harness has no authkey so tailscale-up itself is Condition-skipped);
NEGATIVE: `systemctl stop bulkhead-enforce` ⇒ `attest gate` fails closed FAST (`e0=0` → `not-armed`, no
30s hang), the gate unit goes inactive on restart, and a transient `Requires=`-the-gate unit is refused
to start; then RE-ARM restores a clean gate-passing box for a graceful poweroff.

## Seam

- **Self-asserted, not cryptographic.** The TCB collector reads its OWN pinned maps; there is no nonce,
  AK signature, PCR, or relying-party verification. A sufficiently-privileged IN-TCB compromise that
  flips the maps back to fake-armed, or replaces the collector with one that always returns OK, defeats
  it — exactly as it would forge `attestDigest`. The gate omits the collector-binary-hash field (it adds
  no on-box guarantee — the binary doing the read IS the collector), so it does NOT detect a swapped
  collector. The cryptographic upgrade (same verb/unit/dependency, but `attest verify` against a pinned
  EK-rooted quote + a build-derived expected-D) is the explicit follow-up once reproducible-D lands.
- **Posture, not provenance.** The gate sees enforcement state, not intent — it cannot distinguish a
  deliberate soft-disarm from a malicious `enforce_flags` write (the signed control chain is where
  intent-vs-tamper lives; the gate does not consult it).
- **Only the JOIN is gated**, the lowest-blast-radius action: a box already on the tailnet stays on
  until the session drops, and non-tailnet egress remains the BPF-LSM E2 floor's continuous job.
- **Fail-CLOSED if the collector never binds.** A crash-looping collector (binary present, socket
  never bound) leaves `attest gate` retrying then exiting non-zero — the gate oneshot FAILS, so
  `tailscale-up`'s `Requires=` refuses the join (fail-closed). A genuinely collector-less image
  Condition-skips the gate (the `Requires=` is then vacuously satisfied), but `tailscale-up`'s own
  `ExecStartPre=/usr/bin/bulkhead-collector` cannot exec the absent binary, so the join still
  fail-closes. The `tcb_clean` read's broker dependency is satisfied transitively: the gate is
  `After=bulkhead-enforce.service`, which `ExecStartPre=ctl wait-broker-tcb` blocks on the broker's
  TCB registration, so by the time the gate runs the broker cgroup is present (live boots measure
  `count=3` clean).
