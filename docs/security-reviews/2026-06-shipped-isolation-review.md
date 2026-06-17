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
/data exhaustion (deferred — rotation design), R10 [MED] a GC cgroup-inode-recycle race (**fixed**),
with 4 of 7 refuted. A THIRD, parsing/crypto audit then found R11 [HIGH] a deny-needle scan evaded by
TLS-record fragmentation (**fixed**) and R12 [LOW] an unbounded startup chain read (documented), with
7 of 10 refuted — the canonical-encoding/crypto and agent grammar holding up. A FOURTH, invariant
audit (does each core promise hold in every path?) found **0 violations** — the convergence signal
after three bug-finding lenses; only a runsc least-privilege parity nicety was closed.

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

### R6 [HIGH] — the inspected-egress method allowlist was bypassable by HTTP/1.1 pipelining (reverted, then RE-DONE SOUNDLY)

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
**RE-DONE SOUNDLY (2026-06-17).** The inspect leg is now HTTP/1.1-AWARE: it PARSES each request
(`http.ReadRequest`), vets it whole, and RE-SERIALISES it to the upstream with canonical fixed-length
framing — so the upstream's request boundaries are exactly the proxy's, never the agent's raw bytes,
which forecloses the pipelining/smuggling class BY CONSTRUCTION (every request is framed and gated;
nothing leaves until the whole request is vetted). Ambiguous framing (duplicate Content-Length), h2,
and post-Upgrade websockets fail closed (R4). The method allowlist is its first rule.
`TestInspectRelayPipelineBypass` proves the old bypass is dead (a `POST /evil` pipelined behind an
allowed `GET` is denied AND never forwarded); `make verify-egress-mitm` ARM 5 live-proves the method
deny end-to-end (the agent's GET refused with EOF, a signed Hook=inspect deny reason=method:GET, chain
verifies), with ARMs 1–4 still green (a normal GET still inspects through to HTTP 200).

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

### R9 [HIGH] — a compromised agent can fill the shared 100 MB /data partition (fixed, ADR-0040)

All five signed chains share one `--fixed-size 100M` `/data` partition with no per-chain footprint
bound and no per-tier isolation. A compromised agent generating egress/audit volume fills it; appends
then fail and the fail-closed discipline denies service across tiers (and compounds R8). **Fixed** by
bounded-retention segment rotation (ADR-0040), scoped against a three-way design panel and built
verifier-first (the R8 discipline — no box may meet a segment its verifier can't follow). A chain seals
its live file into numbered segments (`<live>.NNNNNN`) at a byte threshold, keeps a bounded window, and
prunes the rest; rotation is **link-continuous** (prev_hash/seq are not reset), so the verifier checks
the retained segments + live file as ONE chain — a deleted segment breaks the same prev_hash linkage
that already catches a deleted middle subchain, and a *head*-pruned chain is anchored by accepting the
oldest retained record's prev (the cross-prune link is the off-box check, extending ADR-0030's tail
boundary to a bounded head). Per-tier caps `(keep+1)×8 MiB`: five chains = 80 MiB < 100 MB, so the
egress tier physically cannot starve the others. R1 — a rotation fault degrades to "keep writing the
current file", never a failed append, so rotation can never *become* the denial it removes. The one
deliberate trade (pruned-segment tamper detection moves off-box) is owner-noted in ADR-0040.
Live-proven across a reboot on the production image (`make verify-audit-rotation`, 19/19): the egress chain
rotated and HEAD-pruned (so the retained-head anchor is load-bearing), verify-audit OK + footprint bounded,
and the boot gate stayed green over the segmented+pruned chain across a reboot with link-continuous appends.

### R10 [MED] — GC manifest-prune races cgroup-inode RECYCLE (fixed)

`gc.go` snapshotted agent liveness (`liveAgentCgids()`) OUTSIDE `controlMu`, then pruned
`egress_policy` under it. The two-pass `seen` guard does spare a *fresh* launch (a never-witnessed
cgid is never pruned) — but NOT a cgroup-inode RECYCLE: `seen` is never cleared, so a dead agent A's
inode X stays in `seen` forever; if a stale outside-lock scan misses the replacement agent B (which
recycled inode X, cgid == dir inode, ADR-0029) while B's manifest is already written under the lock,
the GC prunes X — deleting B's manifest. B then runs with NO `egress_policy` entry → the BPF E2 hook
`allowed`-lookup misses → unrestricted at E2 (the netns + proxy floor remains, hence MED, not a full
bypass; the per-agent egress-class restriction is lost). **Fixed** (the snapshot is now taken INSIDE
`controlMu`, making it atomic with the broker/ExecStartPre manifest write that is also `controlMu`-
gated: a recycled inode is either already-live by snapshot time, or not-yet-written; either way it is
not wrongly pruned). The latency-vs-race call: the cgroupfs glob over the appliance's few agents is a
negligible added lock-hold, worth closing the recycle race. The prune predicate is unchanged (its
`selectEgressPrunes` tests still pass); the fix is a concurrency *atomicity* change, correct by
construction (snapshot + delete now share the writer's lock). (A separate minor note: `seen` grows
monotonically — a bounded-but-unfreed set; benign once the recycle race is closed.)

### Refuted (4)

Backstopped and refuted: a "collector-restart drops a live class" claim (the PID-1 systemd cgroup
eBPF egress filter holds independently); a stranded `.task` credential (0700-root dir DAC +
ProtectSystem/DynamicUser/empty-caps make it unreadable to the agent); the plaintext seed on `/data`
(0600-root + the non-root confined agent's empty caps); and RAUC reactivating a vulnerable prior slot
(the privileged signed-bundle install boundary gates the precondition).

## Third audit: parsing/crypto lens (2026-06-16)

A third lens — input-validation/parsing robustness + crypto/protocol correctness, where malformed or
adversarial bytes meet a parser, encoder, or crypto primitive. 10 candidates → **3 survived, 7
backstopped**. The canonical-encoding/crypto and the agent grammar held up; the content filter did not.

### R11 [HIGH] — the deny-needle scan was evaded by TLS-record fragmentation (fixed)

The operator deny-needle denylist (`BULKHEAD_EGRESS_DENY_NEEDLES`) scans decrypted agent→upstream
bytes for literal needles across a sliding window. But `inspect()` REPLACED the window with each
buffer (`st.tail = append(st.tail[:0], buf...)`) instead of ROLLING it, so a needle split across 3+
small records was never scanned in one span — and an RCE'd agent controls its TLS plaintext record
sizes (Go's `tls.Conn.Read` returns one record per call). Confirmed empirically: `SECRETTOKEN`
streamed one byte per record slipped through, despite the comment claiming "a needle can't split
across buffers". A needle longer than the fixed 256-byte window was also splittable. **Fixed**
(`cf951ed`): a true rolling window (the last *win* bytes of prior-window ++ buffer, built in a fresh
slice that never aliases the tail), with *win* raised to the longest configured needle.
`TestNeedleScanFragmentation` covers 1-byte/record, a 3-buffer split, and a 300-byte needle. (The
encoded/encrypted-exfil evasion is inherent to any literal denylist and out of scope; this closes the
FRAGMENTATION of a *present plaintext* needle.)

### R12 [LOW] — startup chain readers read the whole file unbounded (documented)

`repairTornTail` (added in R8) and `lastChainHash` `os.ReadFile` the entire chain at open, unlike
`verifyChainState`'s bounded scanner. The audit framed this as a multi-GB OOM, but `/data` is a
`--fixed-size 100M` partition, so the chain cannot exceed ~100 MB — the read is wasteful (≈100 MB ×
three services at boot is not free on a constrained appliance) but not the multi-GB OOM claimed. Fix
shape: a bounded TAIL read (seek to end, read back a capped window for the last record/newline), O(one
record). DEFERRED as a hygiene follow-up — and now much smaller: R9's shipped rotation (ADR-0040) caps
the live file at `rotateBytes` (8 MiB), so `lastChainTip`'s whole-file read is bounded to ~8 MiB per
chain rather than ~100 MB, and the boot gate reads only the retained window (≤16 MiB/chain). The
remaining win (an O(one-record) tail seek) applies to the three byte-identical copies.

### Refuted (7)

The parsers, grammar, protocol, and crypto largely held: the request-line bytes can't smuggle a
newline (`bytes.Fields` strips CR/LF); the Host-coherence check is advisory-only (no deny to bypass);
the quarantine DELEGATE classes are AND-clamped by the kernel-attested mask in the broker regardless
of the in-agent gate; `varName`/`isIdent` rejects multi-token register smuggling; `delegGen` rides the
pidfd-pinned attested cgroup path; the chain-domain binding comes from the root-owned image-baked unit;
a mismatched re-signing CA key fails closed at the handshake. That 7/10 fell — and that the
canonical-vs-json hash encoding (the highest-value forge target) held — is the assurance.

## Fourth audit: invariant lens (2026-06-16) — campaign convergence

The final lens checked bulkhead's CORE PROMISES directly — for each invariant (narrow-never-widen,
fail-closed, record-before-act, single-parse/attested-identity, least-privilege), find any path that
violates it. 8 candidates → **0 survived refutation**. Every apparent violation was upheld by the hard
layer it should be:

- **narrow-never-widen** — the top-level EXPAND ceiling is all-classes, but every EXPAND is operator-
  gated (SO_PEERCRED uid==0 on the 0600 root-only approve socket; a non-root agent cannot approve), and
  R2's `gen>0` refusal closes the delegated-child climb on the kernel-attested path; DELEGATE is a pure
  `parent & requested` intersection.
- **fail-closed** — the BPF E2 enforce fails open-to-observe when unarmed, but it is an additive one-way
  ratchet over a STRUCTURAL deny floor that holds regardless: the agent slice + unit carry
  `IPAddressDeny=any`/loopback-only (a cgroup/skb filter, not the LSM hook), nftables is `policy drop`,
  and the confined agent is in a no-route netns reaching out only via the fail-closed egress proxy. A
  disarmed E2 can only fail to ADD a denial, never open the floor.
- **record-before-act** — the egress proxy records before acting; control-plane record-after-act is R5
  (gated, deferred); the operator CLI `egress set` is E0-bpf-denied to non-TCB callers.
- **single-parse / attested-identity** — the CONNECT host is the sole identity for the dial, the leaf,
  and the SSRF guard (on the resolved IP); SNI/Host are logged cross-checks only; authority keys on the
  SO_PEERPIDFD-pinned cgroup, never an agent-supplied value.
- **least-privilege** — every agent jail is capless + NoNewPrivileges + seccomp + (netns or gVisor);
  the one gap (the runsc bundle omitting `noNewPrivileges`) was backstopped by the empty cap set and is
  now closed for parity (`0b4dc4a`, + `/dev` nosuid/noexec/nodev).

0 invariant violations on the final lens — after three lenses that DID find bugs (R6–R12) — is the
convergence signal: the core promises hold; the issues found were specific implementation bugs (now
fixed), not broken guarantees.

## Audit campaign summary

Four adversarial lenses over the shipped architecture, each candidate refuted before belief:
per-component, cross-cutting (interactions/sequences), parsing/crypto, and invariants. Net outcome —
**confirmed-and-fixed:** R7 (router paid-call cap), R8 (torn-tail brick), R9 (/data exhaustion →
bounded-retention segment rotation, ADR-0040), R10 (GC inode-recycle race), R11 (deny-needle
fragmentation); **reverted-then-re-done-soundly:** R6 (the method-allowlist — the inspect leg is now
HTTP/1.1-aware / parse-and-re-frame, so the pipelining bypass is closed by construction; ADR-0034 inc2
sub-B, live-proven verify-egress-mitm ARM 5);
**documented-deferred:** R5 (control-chain record-after-act, gated), R12 (unbounded startup read, now
≤8 MiB after R9's rotation); plus the runsc OCI hardening. The final invariant
lens found **0 violations**. The signed-chain canonical encoding, the Dual-LLM quarantine, the router,
and the BPF-LSM enforce all withstood adversarial scrutiny. (These audits are in addition to the
earlier per-component review that fixed R1/R2/R4, reclassified R3, and scoped R5.)

## Verification posture

Every R1–R4 change is a single self-contained commit + recipe re-pin, with `main` green at each
checkpoint, and is **live-verified** on the `qemux86-64` wic image (not merely unit-tested) — each
by a tamper/adversarial arm that fails the boundary it concerns. The live checks are the
`verify-egress-gate` (R1), `verify-agent-orch` (R2), `verify-runsc-run` (R3), and
`verify-egress-mitm` (R4) targets, bundled as a re-runnable regression suite: `make
verify-security-review`. R3's live arm went further than confirm-the-fix: its `rw`
counterfactual *reclassified the finding*, which is the intended outcome of building the
counterfactual rather than asserting the fix's rationale.
