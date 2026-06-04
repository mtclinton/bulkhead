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
   collector code, so the genuine code's own clean/anomalous self-assessment is trustworthy.

2. **PCR 14 — extend-only.** PCRs 16/23 are debug/RESETTABLE (a caller at locality 0 can
   `TPM2_PCR_Reset` then re-extend a forged clean value); PCRs 8-15 cannot be reset from locality 0,
   so the only way to a PCR value is to actually extend that digest, one-way. PCR 14 is conventionally
   free in this image. The verifier checks `PCR == H(0^32 || D)` (a single extend from a zeroed bank),
   which ALSO catches any stray pre/post extension. **Trust boundary:** `/dev/tpmrm0` is root-only and
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

4. **AK + freshness.** The AK is a TPM-restricted ECDSA-P256 signing key created under the Owner
   hierarchy with a FIXED template, so the same AK (same pub) is re-derived every boot from the TPM
   hierarchy seed; the verifier pins it out-of-band. *Restricted* means a quote signature can ONLY
   have come from the TPM over a real `TPMS_ATTEST` — it can't be forged by signing a fake blob
   outside the TPM. The verifier's OWN fresh nonce is the quote's `QualifyingData`, checked against
   the verifier's nonce (NOT the envelope's self-reported one), so an old all-green quote can't be
   replayed. The off-box verify checks: magic == `TPM_GENERATED`, `QualifyingData` == the fresh nonce,
   the ECDSA signature under the pinned AK, and the quoted PCR digest == `H(SHA256(H(0^32 || D)))` for
   the expected good D — fail-closed on any mismatch.

`go-tpm` v0.9.8 vendored (builds offline); no change to the verified E0-E3 object or the signed chains.

## Verification

Host `go build`/`vet`/`test` (incl. the OFFLINE `-mod=vendor GOPROXY=off` recipe-flag build, so the
air-gapped Yocto build works). QEMU (`scripts/qemu-attest-check.py` + `make verify-attest`, booted
under `run-qemu-tpm.sh`'s swtpm + tpm-tis): on the hardened image booted E0+E2 armed, assert
`/dev/tpmrm0` exists and `bulkhead-attest.service` extended the TCB digest at boot (via the
collector); then a FRESH nonce → `attest quote` → off-box `attest verify` PASSES (genuine quote +
fresh nonce + AK sig + PCR == expected enforcing-TCB state); and two NEGATIVES fail closed — verify
against a TAMPERED expected digest (a box in a different state than expected cannot pass) and against
a DIFFERENT nonce (no stale-quote replay).

## Seam

HONEST LIMITS, deferred to bare metal (the same split ADR-0008 documents for the sealed key):
- **AK trusted out-of-band.** The swtpm EK cert is self-signed dev PKI, so the verifier pins the AK
  pub TOFU. Full EK-cert credential-activation binding the AK to a manufacturer cert chain — AND
  binding the AK to the ADR-0008 sealed seed (so a box that can't unseal produces neither a valid
  audit chain NOR a recognizable AK, one TPM-rooted identity) — is the bare-metal upgrade.
- **Runtime state, not the boot chain.** Under qemu/OVMF firmware PCRs 0-9 read 0, so this attests
  measured RUNTIME state ("this running collector measured itself as enforcing E0+E2 with these
  binaries + clean TCB"), not a firmware-rooted boot-chain. Full boot-to-runtime coverage needs
  bare-metal firmware PCRs.
- **In-TCB compromise after measurement.** A live root/in-TCB compromise AFTER the extend can quote
  stale-good values — that remains the BPF-LSM floor's job, not this layer's.
- Binding the audit-chain HEADs into the quote (a stable PCR keeps the digest fixed across audit
  events; the HEADs are a follow-up enrichment shipped alongside) + an authenticated nonce→quote
  transport on bare metal (today the qemu nonce→quote is over the trusted console).
