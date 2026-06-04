# ADR-0019: Software-measured-state remote attestation

Status: Accepted
Date: 2026-06-03
Relates to: ADR-0004 (E0–E3 enforce + the TCB model), ADR-0008 (measured boot + the TPM-sealed
audit seed), ADR-0016 (the collector control socket — the bpf()-write/read chokepoint), ADR-0017
(the signed control chain + `canonical()`), ADR-0018 (harden-by-default — the box boots E0+E2 armed).

## Context

After ADR-0018 the box ENFORCES its OS-level guarantees by default and (ADR-0017) records every
authority change on a signed chain. But every guarantee is still SELF-ASSERTED: a tampered box
running a modified collector that flips `enforce_flags` to observe — or adds a stranger to
`tcb_cgroups` — can report all-green, and a remote relying party has no cryptographic way to tell it
apart from a genuinely-enforcing box before releasing keys or work. ADR-0019 closes that: the
collector measures its own running TCB into a TPM PCR and, on a fresh verifier nonce, produces an
AK-signed `TPM2_Quote` an OFF-BOX verifier checks — making the enforcing posture EXTERNALLY PROVABLE.

Feasibility was proven empirically before designing: the rootfs already ships `tpm2-tools`, `go-tpm`
v0.9.8 vendors air-gap-clean (only dep `x/sys`, already vendored; builds offline under the recipe
flags), and the full `PCR_Extend` → `TPM2_Quote` → off-TPM verify + tamper-reject round-trip works on
the harness swtpm. ADR-0008's "firmware PCRs 0-9 read 0 under qemu" does NOT apply — this extends its
OWN chosen application PCR from userspace, orthogonal to firmware measurement and to credential unseal.

## Decision

1. **What is measured** (`attestDigest`, mirroring the audit `canonical()` discipline: a
   domain/version tag `bulkhead-attest-v1`, fixed field order, 8-byte length-prefixes, sorted maps,
   never json): the **collector binary hash** (`sha256(/proc/self/exe)` — catches a modified
   collector, the core forge), the **`enforce_flags` snapshot** sorted by hook id (catches E0/E1/E2/E3
   flipped from enforce to observe — the headline tamper), and the **`tcb_cgroups` membership state**
   measured STABLY across boots as `(count, clean)` where `clean` = the live map is EXACTLY the
   collector's expected TCB set {root, collector, broker}, no stranger (the raw cgids are per-boot
   inodes, so we measure cleanliness, not the inodes). The binary hash anchors trust in THIS
   collector code, so the genuine code's own clean/anomalous self-assessment is trustworthy. This
   measures the enforce POSTURE — which hooks DENY — NOT per-agent `egress_policy`/`grant_once`
   CONTENTS, which are runtime state written per-agent after this boot extend (see the Seam).

2. **PCR 14 — extend-only.** PCRs 16/23 are debug/RESETTABLE (a caller at locality 0 can
   `TPM2_PCR_Reset` then re-extend a forged clean value); PCRs 8-15 cannot be reset from locality 0,
   so the only way to a PCR value is to actually extend that digest, one-way. PCR 14 is conventionally
   free in this image. The verifier checks `PCR == H(0^32 || D)` (a single extend from a zeroed bank),
   which ALSO catches any stray pre/post extension. Critically, the verifier ALSO binds the quote's PCR
   SELECTION to exactly PCR 14 (one PCR, SHA-256 bank): the quote's pcrDigest is `H(selected PCR
   VALUES)` and the PCR *index* is NOT in the digested bytes, so without this a root attacker could
   `TPM2_PCR_Reset` a RESETTABLE PCR (16/23), extend the good D into it, and quote THAT (matching
   pcrDigest) — the selection check is what makes the non-resettability argument actually hold for the
   quote we verify. **Trust boundary:** `/dev/tpmrm0` is root-only and
   the collector is TCB+root; a jailed agent (non-root DynamicUser) cannot open it, so the only
   principal that can extend/reset PCR 14 is the collector. A root attacker cannot reset-then-forge
   (non-resettable) — their only move is running a tampered collector that extends a stale-good D,
   which is the in-TCB-after-measurement limit below, not a PCR weakness.

3. **In-collector via the control socket.** The extend/quote read `enforce_flags`/`tcb_cgroups` —
   `bpf()` syscalls that a non-TCB unit's cgroup CANNOT issue under default-armed E0 (they would
   EPERM). So `attest extend`/`quote` are thin control-socket CLIENTS; the COLLECTOR (TCB) does the
   digest + the TPM ops in-process (new `ATTEST-EXTEND`/`ATTEST-QUOTE` verbs, operator-gated like
   `ENFORCE-SET`: uid-0 + non-agent). `attest verify` is OFF-BOX — no TPM, no maps — and runs anywhere
   (a relying party's machine), mirroring `verify.go`'s offline-verifier discipline. A
   `bulkhead-attest.service` oneshot (post-arm, `ConditionPathExists=/dev/tpmrm0`) runs the boot extend.

4. **AK pin + freshness.** The AK is a TPM-restricted ECDSA-P256 signing key created under the Owner
   hierarchy with a FIXED template, so the same AK (same pub) is re-derived every boot from the TPM
   hierarchy seed. The verifier PINS it out-of-band: `attest verify` REQUIRES the expected AK pub
   (PKIX DER hex or `@file`, captured on a trusted first contact via `attest akpub`) and REJECTS any
   envelope whose AK does not bytewise-match it BEFORE checking the signature. Without that pin the
   verifying key would be read from the attacker-controllable envelope, so ANY genuine TPM — or even a
   hand-rolled software key over a fabricated `TPMS_ATTEST` — could forge a PASS for the expected box;
   the pin is what binds the proof to THIS box. *Restricted* additionally means a quote signature can
   ONLY have come from the TPM over a real `TPMS_ATTEST` — it can't be forged by signing a fake blob
   outside the TPM. The verifier's OWN fresh nonce is the quote's `QualifyingData`, checked against
   the verifier's nonce (NOT the envelope's self-reported one), so an old all-green quote can't be
   replayed. The off-box verify checks, fail-closed on any mismatch: the envelope AK == the pinned AK,
   magic == `TPM_GENERATED`, `QualifyingData` == the fresh nonce, the ECDSA signature under that pinned
   AK, the quote selects EXACTLY PCR 14 (SHA-256), and the quoted PCR digest == `H(SHA256(H(0^32 ||
   D)))` for the expected good D.

`go-tpm` v0.9.8 vendored (builds offline); no change to the verified E0-E3 object or the signed chains.

## Verification

Host `go build`/`vet`/`test` (incl. the OFFLINE `-mod=vendor GOPROXY=off` recipe-flag build, so the
air-gapped Yocto build works). QEMU (`scripts/qemu-attest-check.py` + `make verify-attest`, booted
under `run-qemu-tpm.sh`'s swtpm + tpm-tis): on the hardened image booted E0+E2 armed, assert
`/dev/tpmrm0` exists and `bulkhead-attest.service` extended the TCB digest at boot (via the
collector); the AK pub is captured TOFU (`attest akpub`); then a FRESH nonce → `attest quote` →
off-box `attest verify` against the PINNED AK PASSES (genuine quote + fresh nonce + pinned-AK sig +
PCR-14 selection + PCR == expected enforcing-TCB state); and THREE NEGATIVES fail closed — verify
against a TAMPERED expected digest (a box in a different state than expected cannot pass), against a
DIFFERENT nonce (no stale-quote replay), and against a WRONG/different AK pub (a forged or other-box
envelope is rejected by the pin — the regression test for the AK-pinning fix).

## Seam

HONEST LIMITS, deferred to bare metal (the same split ADR-0008 documents for the sealed key):
- **AK pin is TOFU; EK-cert binding deferred.** `attest verify` ENFORCES an out-of-band AK pin (the
  operator captures the AK pub on first contact via `attest akpub` and supplies it; a non-matching
  envelope AK is rejected before the signature is checked). What remains deferred to bare metal is
  rooting that pin in the TPM's EK cert via credential-activation — AND binding the AK to the ADR-0008
  sealed seed (so a box that can't unseal produces neither a valid audit chain NOR a recognizable AK,
  one TPM-rooted identity). Under qemu the swtpm EK cert is self-signed dev PKI, so first-contact TOFU
  is the trust root.
- **Per-agent egress/grant CONTENTS are runtime state, not in D.** D attests the enforce POSTURE —
  which hooks (incl. E2's `socket_connect`) are in enforce mode — plus the collector binary and TCB
  cleanliness. It does NOT attest the per-agent `egress_policy` manifests or the one-shot `grant_once`
  grants: those are written per-agent at spawn (AFTER the post-arm boot extend), are policy-dependent
  and dynamic, and so cannot live in a stable, reproducible boot-snapshot digest — folding them in
  would be either vacuous (the maps are empty at extend time) or racy/policy-specific. So `E0+E2
  armed` here means the hooks DENY, not that a given agent's manifest is restrictive (an agent
  legitimately allowed public egress carries `DST_PUBLIC` by policy). Attesting per-agent policy
  CONTENTS would need a different protocol — per-agent, quote-time, against a relying-party-supplied
  expected manifest — a genuine follow-up; continuous per-agent enforcement stays the BPF-LSM floor's
  job, same class as the in-TCB-after-measurement limit.
- **Runtime state, not the boot chain.** Under qemu/OVMF firmware PCRs 0-9 read 0, so this attests
  measured RUNTIME state ("this running collector measured itself as enforcing E0+E2 with these
  binaries + clean TCB"), not a firmware-rooted boot-chain. Full boot-to-runtime coverage needs
  bare-metal firmware PCRs.
- **In-TCB compromise after measurement.** A live root/in-TCB compromise AFTER the extend can quote
  stale-good values — that remains the BPF-LSM floor's job, not this layer's.
- Binding the audit-chain HEADs into the quote (a stable PCR keeps the digest fixed across audit
  events; the HEADs are a follow-up enrichment shipped alongside) + an authenticated nonce→quote
  transport on bare metal (today the qemu nonce→quote is over the trusted console).
