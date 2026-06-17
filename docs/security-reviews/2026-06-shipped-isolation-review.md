# Security review — shipped agent-isolation architecture (2026-06)

Status: 3 confirmed wiring-gap findings (R1, R2, R4) fixed + live-verified; R3 **reclassified** by
its own live counterfactual from a MED DoS to a defense-in-depth hardening (the DoS was not
exploitable in the rootless config — see below); R5 accepted-and-deferred. The review also
re-examined four adjacent boundaries (the audit-chain verifier, the Dual-LLM quarantine, the router
model-routing leg, and the BPF-LSM action-auth enforce) and found them **gap-free** — so the pass
covers the whole shipped isolation architecture, network and syscall halves, not only where it broke.
A follow-up multi-agent adversarial audit (2026-06-16, see below) then found + **reverted** one HIGH
(R6, a pipelining bypass in this session's OWN just-shipped method-allowlist), shipped an opt-in
mechanism for one MED (R7, a router paid-call denial-of-wallet cap), and saw 17 of 19 candidates
refuted by independent skeptics. A SECOND, cross-cutting audit (interactions/sequences/races) then
found three more the per-surface pass missed: R8 [HIGH] torn-tail fusion (**fixed**), R9 [HIGH] shared
/data exhaustion (deferred — rotation design), R10 [MED] a GC↔launch race (deferred — a design
trade-off), with 4 of 7 refuted.

## Scope

An adversarial review of bulkhead's **already-shipped** security architecture — not the
roadmap, but the code on `main`:

- the egress boundary (ADR-0034: structural confinement + the mediating proxy + the signed chain),
- broker-mediated delegation (ADR-0006/0015/0037: narrowed children, depth/width caps, attested authority),
- the gVisor substrate (ADR-0031: the default tier, minimal-rootfs OCI bundle, mediated UDS legs).

The review looked for one specific class of bug: a **wiring gap** — a guarantee the design
intends, that turns out to be enforced at a *softer* layer than the threat model assumes. The
fix in every case is to move the enforcement down to the hard layer a compromised agent cannot
reach.

## Cross-cutting theme

Each finding had the same shape — an enforcement living one layer too high:

| Found enforcing at (soft) | Should enforce at (hard) |
|---|---|
| systemd `Before=` ordering (does not propagate failure) | systemd `Requires=` (R1) |
| an in-jail `Environment=` flag (a compromised agent ignores it) | the TCB, keyed on kernel attestation (R2) |
| an implicit "best effort, else pass through" | fail closed (R4) |

A compromised agent or a tampered `/data` is *assumed* by the threat model; a guarantee that
only holds when neither is true is not a guarantee. These three close that gap. (R3 looked like a
fourth — an `rw` bind-mount default — but its live counterfactual showed the protection was already
hard, at the kernel's user-namespace DAC; see R3 below.)

## Findings

### R1 [HIGH] — the untrusted-web chokepoint did not honor the fail-closed audit gate

The egress proxy is the single mediated path for untrusted web. The boot self-test gates the
TCB closed on a forged/gapped `/data` audit chain — but the proxy was only `Before=`-ordered
after the verifier, and `Before=` does **not** propagate failure. A tampered chain therefore
refused the collector (TCB) yet still granted the agents web egress: the loudest possible
boundary, silently open.

Fix: the proxy now `Requires=bulkhead-selftest.service` (which on Yocto `Requires=` the chain
verifier), mirroring the trusted router leg. A forged chain refuses the proxy **and**
transitively every confined/runsc agent that `Requires=` it.

Fix: `d80487d`. Verify: `make verify-egress-gate` — single-boot tamper test; a forged record
makes `verify-audit` fail, `systemctl start` of the proxy is refused, and a confined agent
cannot start. (The destructive test forges into `/data`, so its harness runs the VM under
`snapshot`; `ac67986`.)

### R2 [HIGH] — a delegated child's egress-widen cap lived in the jail, not the TCB

A broker-minted delegated child must never widen its egress past its delegation root (the
grandchild ⊆ child ⊆ parent lifetime invariant the depth/width caps enforce). But the broker's
`EXPAND` handler never checked delegation generation: `NO_EXPAND` was only an `Environment=`
flag inside the **untrusted** agent runtime. A compromised child could `exec
bulkhead-collector expand` (or write `EXPAND` to the broker socket) directly, bypassing its own
runtime, and the broker would mint a wider mask.

Fix: the broker (TCB) now refuses `EXPAND` from any child whose **kernel-attested** cgroup path
has delegation generation > 0 — the same un-spoofable signal the depth cap already trusts.
Top-level agents (gen 0) still `EXPAND` with operator approval.

Fix: `bb70990`. Verify: `TestExpandRefusedForDelegatedChild` (broker unit) + `make
verify-agent-orch` (full delegation chain + depth cap, no regression). The attestation that
yields the correct generation is itself live-proven by the depth-cap arm (`ARM DEPTHCAP`).

### R3 [MED → reclassified to defense-in-depth] — the substrate's mediated UDS legs were writable

A gVisor-tier agent reaches the host proxy/router through two UDS legs bind-mounted from
`/run/bulkhead-{egress,router}`. They were mounted `rw`. The finding's **premise** was that a
sandboxed agent could therefore `unlink`/replace the shared `egress.sock`, removing every other
tier's only way out.

Fix: mount both legs `ro`. `connect()` still works (the agent keeps its mediated egress); the
agent has no business writing the leg dir.

**Live verification reclassified this from a MED DoS to a defense-in-depth hardening.** The `rw`
counterfactual showed the cross-tier write is refused **even with the leg mounted `rw`** — so the
load-bearing control is the **rootless user-namespace DAC**: runsc's gofer maps to host-nobody for
the proxy-owned, mode-`0755` leg dir and cannot write it regardless of the mount flag. The DoS was
therefore **not exploitable** in the rootless config. The `ro` mount is genuine least-privilege and
becomes load-bearing only for a non-rootless / root-gofer tier (where the userns remap would not
apply), so it is kept as defense-in-depth — not reverted.

Fix: `d4b08a0` (kept). Verify: `make verify-runsc-run` — the agent loop reaches HTTP 200 through
the `ro` leg; `probe-romount` shows `unlink`/`create` REFUSED; the `rw` counterfactual shows the
write *still* REFUSED, attributing the protection to the userns DAC (`8cb8f1a`). gVisor surfaces
the refusal as `EACCES`/`EPERM`, not Linux's `EROFS`.

This is the point of an adversarial counterfactual: it falsified the finding's premise before the
fix could ship on a false rationale, and it pinned down *which* layer actually holds the line.

### R4 [MED] — content-inspection failed *open* when it couldn't terminate

An operator marks a host `inspect` to see inside it (TLS-terminate + content-inspect). But the
proxy only terminated when a re-signing CA was loaded **and** the port was a TLS port; every
other case — crucially a CA that failed to load — fell through to an opaque passthrough splice.
A missing CA therefore silently downgraded **every** inspect host to uninspected egress while
the operator believed they were inspected.

Fix: decide the disposition **before** dialing. An inspect host the proxy cannot terminate (no
CA, or a non-TLS port) is now **denied** — the chain signs a single deny
(reason=`inspect-unavailable`) and the upstream is never reached, rather than dialing out and
signing a misleading "allow". `inspect` now means *inspect or refuse*; a host meant to ride
opaque must be marked `pinned`/passthrough.

Fix: `30e29b9`. Verify: `TestHandleConnInspectUnavailableDenies` (proxy unit: single deny,
upstream never dialed) + `make verify-egress-mitm` ARM 3 (an inspect host on a non-TLS port is
refused, no inspect/passthrough record written).

## R5 [LOW] — accepted and deferred (now precisely scoped)

The collector's control-plane handlers (`src/collector/control.go`: `ctlEgressSetSelf`,
`ctlEgressClearSelf`, `ctlGrantClearSelf`, `ctlTcbRegisterBroker`, …) apply the authoritative BPF
**map write first** and then call `recordControl` — which is a `void`, best-effort append: on an
append failure it only `log.Printf`s, with no way to signal the caller. So a control-plane authority
change can be **live in the map while its signed record is missing** (only an un-chained log line
notes the failure) — the inverse of the egress proxy's record-**before**-act, fail-closed discipline.

Why LOW (not MED): the control socket is `0660`-root — **not agent-reachable** (an untrusted agent
cannot invoke these verbs; only the broker / privileged root units can), and the chain lives on
root-owned `/data` a jailed agent cannot fill to force the append error. This is an
integrity-of-record gap reachable only from the root TCB context, not an untrusted-agent boundary.

Fix shape (deferred): make `recordControl` **return** its error and record-**before**-act — append
the signed record durably first, then apply the `m.Update`; if the append fails, refuse the verb (and
roll back any map touch) so no authority change is ever live un-chained. Deferred because it is a
collector-TCB hot-path change with append-durability ordering implications and, per the project's
collector-hardening posture, wants explicit **owner sign-off** rather than being bundled into this
review.

## Boundaries re-examined and confirmed solid

The review also adversarially re-read four boundaries the fixes lean on and found **no gap** —
recorded so the review's scope is the whole picture, not only what broke:

- **The signed audit-chain verifier** (`src/collector/verify.go`) — the root of trust R1's gate
  rests on. It detects every tampering class structurally: record modification (hash mismatch),
  insertion of a forged record (well-formed JSON still hits the ed25519 signature + hash/prev
  checks), mid-record or whole-subchain deletion (continuous `prev_hash` linkage break),
  reordering / illegal seq-reset (seq monotonicity within a per-boot subchain), and domain confusion
  (the domain is folded into the hash). The only un-detected case is **tail-truncation of committed
  records** — a documented, off-box-mitigated boundary (ADR-0025/0026: `--expect-tip` binds the
  verified tip to a quote's HEAD, `--since` proves descent). Extensive existing tests corroborate
  (tamper, subchain-deletion, wrong-domain, torn-tail, rollback, invalid-UTF8, garbage-envelope).
- **The Dual-LLM quarantine taint-flow** (`src/agent/planexec.go` + `qresponse.go`, ADR-0036). The
  CaMeL property holds by construction: a FETCH target, an EXTRACT question, and a DELEGATE
  suffix/classes are all plan-fixed **literals** (a `$var` in any of those slots is grammar-rejected
  fail-closed); raw fetched bytes (`vBody`) can ONLY be routed through the quarantined reader (no
  tools, fresh context, reply stored as DATA and never `parse()`/`dispatch()`-ed), and its result
  (`vData`) can ONLY be REPORTed or used as a DELEGATE **task** — which the broker delivers as a
  `0400` credential and which can direct WHAT a child does but never widen its authority (child =
  classes ∩ parent, broker + E2 enforced; even an injected child-planner's wider class request is
  AND-clamped). The FETCH body is bounded (`fetchBodyCap`). No taint path to control flow or
  authority was found.
- **The router's model-routing leg** (`src/router/`, ADR-0002) — the *other* mediated channel. The
  agent picks a model NAME that maps to a CONFIGURED provider backend, never a URL it controls (no
  SSRF); each provider base is pinned to its exact host (`api.anthropic.com`, `api.openai.com`,
  `generativelanguage.googleapis.com`) over https, validated at startup (`log.Fatalf` on violation).
  The upstream API key is per-backend, sent only to its validated host, never logged or echoed, and
  the shared HTTP client REFUSES redirects specifically so a cross-host 30x cannot exfiltrate the key
  (Go retains auth headers across a redirect). The bulkhead `route` field is stripped before
  forwarding; the client route is downgrade-only (an agent cannot force the paid tier —
  denial-of-wallet), the length gate counts runes not bytes (no multi-byte bypass), `max_tokens` is
  clamped, and upstream error bodies are logged server-side, not echoed to the agent. No gap found.
- **The BPF-LSM action-authorization enforce** (`src/collector/provenance.bpf.c`, E0–E3,
  ADR-0004/0011) — the foundational kernel guarantee, the syscall/resource half of isolation. Every
  hook keys on `bpf_get_current_cgroup_id()` (the kernel's un-spoofable cgroup identity, never
  anything the agent supplies); it is a one-way ratchet (a prior LSM deny is never reverted to
  allow); only TCB cgroups are always-allowed, and TCB registration is anti-arbitrary (the caller's
  attested cgroup must string-equal the fixed broker cgroup — `control.go`). The opt-in
  observe-unless-armed posture is fail-open BY DESIGN, but every enforce is defense-in-depth atop the
  structural jail (the no-route netns for E2 egress; `NoNewPrivileges` + an empty capability set for
  E0/E3), so an unarmed hook never means an unconfined agent — and the arming is live-proven from
  cold boot (`verify-hbd`). E0 (bpf) is ungrantable by construction; the one-shot operator grant is
  atomic and un-replayable (a single `CMPXCHG(1→0)` picks exactly one winner; a miss / TTL-lapse /
  corrupt count all fail closed to a normal deny). No gap found in the enforce design, verdict logic,
  cgroup identity, ratchet, or grant path.

## Follow-up: multi-agent adversarial audit (2026-06-16)

A second, deeper pass: 8 parallel adversarial auditors (proxy, broker, BPF-LSM, quarantine, router,
audit-chain, substrate/units, build/supply-chain), with **each candidate finding adversarially
REFUTED by an independent skeptic before being believed** — the R3 counterfactual discipline applied
at scale. 19 candidates → **2 survived refutation, 17 were backstopped**.

### R6 [HIGH] — the inspected-egress method allowlist was bypassable by HTTP/1.1 pipelining (fixed by revert)

Found in code this same session had just shipped. The method allowlist
(`BULKHEAD_EGRESS_INSPECT_METHODS`) checked the method only ONCE, against the first request line,
inside `if !st.hdrParsed` of a raw byte relay. A compromised agent (the threat model) writes
`GET /ok\r\n\r\nPOST /steal\r\n\r\n<secret>` into one terminated TLS record: `inspect()` sees
method=GET, allows, and relays the whole buffer (POST + body) upstream — the check never sees the
POST. Confirmed empirically against the real `inspect()`. A control a compromised agent trivially
bypasses is a false guarantee, so the feature was **REVERTED** (`f5a2ad2`) rather than patched in
place. A sound request-line rule engine requires the inspect path to become HTTP/1.1-aware (frame
each request by Content-Length/Transfer-Encoding, rule-check per request, fail closed on un-parseable
framing or non-HTTP/1.1) — recorded in ADR-0034 as the requirement for a correct re-attempt.

### R7 [MED] — the router has no paid-call volume cap (denial-of-wallet residual) — MECHANISM SHIPPED

The router's only denial-of-wallet control was the per-request TIER gate (downgrade-only route + the
rune-length threshold to the paid path). Both are correct, but they gate one request's tier, not the
VOLUME. A compromised agent reaching the router UDS with an attacker-controlled body can loop
threshold-length, max-`max_tokens`, most-expensive-model requests — each a legitimate paid call — and
nothing bounded the loop, so the operator's API bill grew without limit.

The **mechanism** is now shipped: `BULKHEAD_ROUTER_PAID_RATE_PER_MIN=N` caps paid (RouteAPI) calls at
N/minute via a global token bucket; once the budget is spent a paid request is refused with 429
**before any upstream call** (and before the routing commit — a refusal is logged, not a signed
routing decision). It is GLOBAL (a single-purpose appliance bounds its TOTAL spend, avoiding keying on
the transient DynamicUser uids), and the local/free route is never throttled. Verified by an
integration test driving the real `handleChat` path (cap=2 → the 3rd paid call gets 429, upstream hit
only twice) + a token-bucket unit test. DEFAULT is `0` = unlimited (zero behaviour change): the cap is
opt-in and the **rate N is the operator's policy** — the review shipped the tool, not the policy.

### Refuted (17) — high-confidence assurance

The other 17 candidates were backstopped by a harder layer: e.g. the runsc `/dev` tmpfs missing
nosuid/noexec is mooted by the empty CapabilityBoundingSet (no CAP_MKNOD) + the rootless userns; the
control-chain append-swallow (the R5 area) is gated by the 0660-root socket; a torn-tail re-anchor is
the documented ADR-0026/0030 tail boundary; the RAUC no-downgrade hook is backstopped by rauc's
native serial floor; HTTP/2 bypassing `parseHead` is mooted by the structural proxy-mediation
(uninspected like passthrough — not a NEW exploit). That 17/19 candidates fell to independent
skeptics is itself the assurance: the boundaries the first pass confirmed hold up under a second,
adversarial, multi-perspective look.

## Second audit: cross-cutting lens (2026-06-16)

The first audit was per-component; this one targeted what lives BETWEEN components — concurrency/TOCTOU,
boot/shutdown sequencing, cross-component trust handoffs, state persistence/recovery, aggregate
resource exhaustion — again refuting each candidate. 7 candidates → **3 survived, 4 backstopped**. It
found three real issues the per-surface pass and the first review both missed.

### R8 [HIGH] — torn-tail FUSION false-bricks the box (fixed)

A power-loss can leave `append()`'s `"line\n"` written WITHOUT its `\n`. The verifier tolerates that
fragment while it stays last, so the next boot comes up — but `openAuditLog` reopened `O_APPEND`
without repairing the missing newline, so the first new append FUSED onto the fragment
(`{frag…{seq:1…}\n`), a malformed two-records-on-one-line. Once a second record lands, the fused line
is no longer last, so the boot AFTER fails verify-audit → the R1 fail-closed gate blocks the collector
+ every agent and withholds rauc-mark-good (a spurious A/B rollback of a good slot). A single unclean
shutdown false-bricks the appliance two boots later; all five `/data` chains shared the pattern.
Confirmed by end-to-end reproduction. **Fixed** (`cacfafe`): `openAuditLog` now truncates the un-acked
partial tail before continuing the chain (NOT "append a separating newline" — the audit showed that
bricks differently), applied byte-identically in collector/proxy/router. `TestTornTailNoFusionAcrossReopen`
reproduces the exact power-loss→reopen→2-record→verify sequence against the real code.

### R9 [HIGH] — a compromised agent can fill the shared 100 MB /data partition (deferred)

All five signed chains share one `--fixed-size 100M` `/data` partition with no per-chain footprint
bound and no per-tier isolation. A compromised agent generating egress/audit volume fills it; appends
then fail and the fail-closed discipline denies service across tiers (and compounds R8). Fix shape: a
per-chain on-disk footprint bound with **rotation that carries the tip hash forward** (seal+rename a
chain over N MB so cross-boot `prev_hash` continuity survives the rotation, and the verifier handles
rotated segments) + per-tier disk isolation. DEFERRED: rotating a hash-chained, signed, boot-gated log
while preserving cross-boot verifiability is a substantial design increment — the owner's to scope.

### R10 [MED] — GC manifest-prune races the agent launch (deferred)

`gc.go` snapshots agent liveness (`liveAgentCgids()`) OUTSIDE `controlMu`, then prunes `egress_policy`
under it. A child launched in that window (its manifest set under the lock) is absent from the
pre-lock snapshot, so the GC prunes its manifest → the child runs with NO manifest → unrestricted at
the BPF layer (netns-bounded, hence MED, not a full bypass). The simple fix (snapshot under the lock)
**reverses a deliberate design choice** — the code comment keeps the cgroupfs scan out of the lock for
latency; a cleaner variant re-checks each prune candidate's liveness under the lock. DEFERRED: the
latency-vs-race trade-off is the owner's documented choice to revisit.

### Refuted (4)

Backstopped and refuted: a "collector-restart drops a live class" claim (the PID-1 systemd cgroup
eBPF egress filter holds independently); a stranded `.task` credential (0700-root dir DAC +
ProtectSystem/DynamicUser/empty-caps make it unreadable to the agent); the plaintext seed on `/data`
(0600-root + the non-root confined agent's empty caps); and RAUC reactivating a vulnerable prior slot
(the privileged signed-bundle install boundary gates the precondition).

## Verification posture

Every R1–R4 change is a single self-contained commit + recipe re-pin, with `main` green at each
checkpoint, and is **live-verified** on the `qemux86-64` wic image (not merely unit-tested) — each
by a tamper/adversarial arm that fails the boundary it concerns. The live checks are the
`verify-egress-gate` (R1), `verify-agent-orch` (R2), `verify-runsc-run` (R3), and
`verify-egress-mitm` (R4) targets, bundled as a re-runnable regression suite: `make
verify-security-review`. R3's live arm went further than confirm-the-fix: its `rw`
counterfactual *reclassified the finding*, which is the intended outcome of building the
counterfactual rather than asserting the fix's rationale.
