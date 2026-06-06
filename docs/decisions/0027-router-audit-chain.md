# ADR-0027: the router's signed routing-decision audit chain

Status: Accepted
Date: 2026-06-05
Relates to: ADR-0002/0003 (the provider-pluggable router), ADR-0017 (signed audit chains + verify-audit
+ F4 domain tags + F5 cross-boot linkage), ADR-0008 (the TPM-sealed audit seed), ADR-0026 (the no-rewind
verdict). Gives the model-ROUTING pillar the accountability the isolation/authorization pillars have.

## Context

The three thesis pillars are agent ISOLATION, action AUTHORIZATION, and model ROUTING. Isolation and
authorization got deep, tamper-evident signed audit chains (collector provenance, broker decisions) and a
full attestation line (ADR-0019..0026). ROUTING was the laggard: the router logged each routing decision
with a bare `log.Printf` (`route=%s reason=%q model=%q promptlen=%d`, server.go:91) — ephemeral, no
sequence, no hash chain, no signature, no tamper-evidence. A box could route a prompt to a paid provider
and leave no accountable, verifiable record.

## Decision

The router now appends every routing decision to an ed25519-signed, sha256 hash-chained, domain-tagged
(`"router"`) log — the SAME format the collector/broker use, so the existing `bulkhead-collector
verify-audit` (including the ADR-0026 no-rewind verdict) checks it unchanged.

- **Code reuse by COPY (Option A).** The router is a separate, stdlib-only Go module and cannot import the
  collector package, so the audit primitives (`auditLog`/`auditRecord`/`canonical`/`append`/`openAuditLog`/
  `loadSigningKey`/`lastChainHash`) are copied into `src/router/audit.go`. `canonical()` MUST stay
  byte-identical across the two modules or the collector's verifier rejects router records — a golden
  vector (`835f49b5…`) is pinned in BOTH modules (`src/router/audit_test.go` + the collector's
  `TestCanonicalRouterDomainGolden`), so CI fails on any drift before it ships. (A shared `src/audit`
  module is the eventual DRY refactor; copy-with-golden is the lower-risk v1.)
- **Record overload, like the broker.** Routing decisions overload the six chained fields: `Hook="route"`,
  `Decision=`the route (`local`/`api`), `Mode=`the evidence (`reason=… model=… promptlen=…` plus
  `provider=…` — the outbound destination — for an api route). One signed record per decision.
- **Concurrency (router-specific).** Unlike the collector (single event loop) / broker (single control
  loop), the router's HTTP handlers run concurrently, so `append()` is serialized by a `sync.Mutex`
  (`TestConcurrentAppend` proves it under `-race`: a contiguous, prev-linked chain).
- **Fail-closed.** A routing decision is recorded BEFORE it is acted on; if the append fails the request
  is refused (HTTP 500) — the broker's precedent, accountability is load-bearing, not best-effort. If the
  chain can't be opened at startup the router refuses to start.
- **Verification.** `chainDomain` gains the `audit-router` → `"router"` case, so verify-audit + the
  no-rewind verdict work on the router chain with no other change.
- **Bounded untrusted input (adversarial-review fix).** The client-supplied `model` is the only untrusted
  field written into a record; it is capped (`maxAuditModelLen`) in `recordRoute` so a flood of
  oversized-model requests cannot grow the chain unboundedly and exhaust disk (a network-facing DoS). The
  cap bounds the audit EVIDENCE only — the full model still drives routing/proxying, and `promptlen`
  records the true request size.

## Verification

`go build`/`vet`/`test`/`test -race` green across both modules. Router unit tests: the pinned canonical
golden (matched in the collector), a signed round-trip (seq/prev-link/hash/sig), and concurrent append
under `-race`. Live (Buildroot image, `make image && make data-disk && make qemu-router`): the router
serves; a short prompt routes local + a long prompt routes api, each writing a signed record; in-VM
`verify-audit` on `/var/lib/bulkhead/audit-router/provenance.jsonl` is OK; `--since` the tip is no-rewind
CLEAN; `--since` a bogus head is detected REWOUND/FORKED; `--expect-tip` ties to the verified tip. A
broken audit path surfaces as the router failing to start / 500ing — caught by the existing routing checks.

## Seam

- **Key (v1, Buildroot).** The router uses `loadSigningKey`'s ephemeral per-boot fallback (verified via the
  exported `audit-pub.txt`) on the Buildroot image — enough to prove the signed chain + verify-audit +
  no-rewind end-to-end.
- **Key (production, Yocto) — now wired.** PRODUCTION on the read-only-rootfs Yocto appliance uses a STABLE
  sealed seed for cross-boot verification. The Yocto-only `bulkhead-router-data.conf` drop-in (installed as
  `bulkhead-router.service.d/12-data-persistence.conf`, sorting after the Buildroot `11-audit.conf`)
  redirects `BULKHEAD_AUDIT_DIR` to `/data/bulkhead/audit-router` and `LoadCredential`s the TPM-sealed
  `audit-seed` with `BULKHEAD_REQUIRE_SEALED_KEY=1` (fail-closed). The three design proposals converged on
  SHARING the existing sealed seed (domain-separated by the `"router"` tag) — same TPM/boot/admin, so a
  separate seed adds operational complexity without reducing the real blast radius, while domain tags +
  file isolation contain a network-facing-router compromise to its own chain. The DynamicUser perms problem
  (the router's uid differs each boot, so it can't OWN a persistent `/data` dir) is solved with a fixed
  `bulkhead-audit` system group baked into `/etc/group` at image build (`bulkhead-image.bb`, `extrausers`):
  a `+`-privileged `ExecStartPre` creates the chain dir `root:bulkhead-audit`, setgid `2770`, and
  group-write-enables any prior-boot chain files, and the router joins the group via `SupplementaryGroups`
  — so whichever dynamic uid runs can append the same persistent chain. The boot gate gains a
  `verify-audit /data/bulkhead/audit-router/provenance.jsonl` line (verified against the same sealed seed),
  and the seal + verify-audit units order `Before=bulkhead-router.service`. The `bulkhead-router`,
  `bulkhead-collector`, and `bulkhead-units` recipes are pinned to the ADR-0027 source (`e3239ef`) so the
  image carries the router's audit-chain binary, the `audit-router`→`"router"` verify-audit case, and the
  `11-audit.conf` overlay.
- **Live-verified — and the gate must hold `CAP_DAC_READ_SEARCH`.** Booted live under swtpm
  (`scripts/qemu-yocto-router-check.py`, two boots via an in-guest reboot): all 19 checks pass — the group is
  baked, the chain persists on `/data` signed by the sealed seed, the verify-audit gate passes on BOTH boots
  (verifying the persisted chain against the sealed seed before the router restarts), the chain survives the
  reboot, and the second boot APPENDS to it (no-rewind CLEAN; dir `2770 root:bulkhead-audit`, file
  group-writable `0660`). The live boot caught a real fail-closed BUG that static review and unit tests both
  missed: the verify-audit gate ran as capability-less root, which reads the collector/broker chains
  (`0600 root:root`, as owner) but NOT the router's DynamicUser-owned `0600` chain —
  `open .../audit-router/provenance.jsonl: permission denied` failed the gate CLOSED and bricked the boot.
  Fix: grant the gate the read-only `CAP_DAC_READ_SEARCH` (deliberately NOT the write-capable
  `CAP_DAC_OVERRIDE`), so it can read any chain regardless of owner while remaining unable to modify one — the
  "read-only verifier" property holds.
- **Honest limit.** Like every ADR-0017 chain, this gives tamper-EVIDENCE + non-repudiation AFTER the
  fact, not protection against a compromised router altering its own decisions before signing — that is
  the BPF-LSM floor's and the network-isolation's job. The signed chain proves what a relying party can
  later verify, fail-closed.
