# ADR-0023: Cryptographic self-check gate — the on-box TPM-signed half of the load-bearing gate

Status: Accepted
Date: 2026-06-04
Relates to: ADR-0018 (harden-by-default — boots E0+E2 armed), ADR-0019 (remote attestation: the quote
+ the 5 verify checks), ADR-0020 (EK-cert AK-rooting), ADR-0021 (the posture map-read GATE, the
non-cryptographic half), ADR-0022 (reproducible expected-D, the prerequisite that unblocks this slice).

## Context

ADR-0021 made the tailnet join FAIL CLOSED unless the box is in the expected enforcing posture — but
its predicate is a LIVE MAP READ (`gatePosture()` reads `enforce_flags`/`tcb_cgroups`). That is
SELF-ASSERTED: the collector is the TCB, so a tampered collector that flips the enforce flags to
observe and then LIES about the maps defeats it. ADR-0021 names the cryptographic self-verify as the
explicit follow-up; ADR-0022 (reproducible expected-D) removed its last blocker (the verifier no longer
sources D from the box's own journal).

This ADR ships that follow-up: a SECOND gate that depends on a TPM-SIGNED proof, not a map read.

## Decision

1. **The self-check** (`doAttestSelfCheck()`, in the collector/TCB). On a fresh `crypto/rand` nonce,
   the box produces an AK-signed `TPM2_Quote` of PCR 14 (the exact ADR-0019 `doAttestQuote` path) and
   runs the SAME five verify checks (factored into `verifyEnvelopeChecks`) against the expected
   DEFAULT-ARMED D it derives from its OWN `/proc/self/exe` via the shared `expectedDefaultArmedD`
   (the ADR-0022 posture: E0+E2 enforce, E1/E3 observe, tcb clean count=3). The nonce is generated
   per-call, so the proof can never be a replay of a stored quote.

2. **Pin sourcing — avoid the circularity trap.** The box must NOT pin its OWN freshly-derived AK as a
   trusted IDENTITY (a tampered collector would pin its forged AK and self-pass). So:
   - **Pre-provisioned EK-rooted pin** (`/data/bulkhead/attest-ak.pin`, written by a ONE-TIME OFF-BOX
     ADR-0020 enroll): when present, the quote's AK must bytewise-match it — REAL this-TPM identity.
   - **Structural fallback** (no pin file): verify against the quote's OWN AK. This still adds
     genuine-TPM (magic) + freshness (our own nonce) + sig-consistency + boot-PCR == expected-D over
     the map read, but makes NO identity assertion — it does not treat the self-captured AK as "the
     trusted box". Honest by construction; this is the shipped default under qemu (no `/data` pin).

3. **A SECOND unit, AUGMENT not REPLACE** (`bulkhead-attest-selfcheck-gate.service`). A crypto gate
   needs a TPM, so it `ConditionPathExists=/dev/tpmrm0` — on a legitimately TPM-LESS but enforcing box
   it cleanly SKIPS (systemd treats a skipped `Requires=` dependency as satisfied). It is LAYERED on
   top of the UNCONDITIONAL ADR-0021 map-read gate (conditioned on the collector BINARY, not the TPM),
   which keeps gating the no-TPM box. `tailscale-up.service` `Requires=+After=` BOTH gates. Replacing
   the map read with a crypto-only gate would FAIL-OPEN the no-TPM box — the regression this avoids.
   The selfcheck-gate orders `After=bulkhead-attest.service` so PCR 14 already holds the boot extend.

## What it proves — and explicitly does NOT

PCR 14 holds the BOOT `attest extend` of D (one-way, extend-only). A pass proves the genuine TPM signed
a FRESH quote whose PCR == H(0^32 || expected-default-armed-D) — the box BOOTED in the expected
default-armed posture, the quote is genuine + fresh + covers exactly PCR 14, not replayed. It CATCHES a
never-armed box whose tampered collector merely fakes the live map (the boot-extended PCR would differ,
and the genuine TPM cannot be made to sign a matching pcrDigest), and software-forged / replayed quotes.

It does NOT catch a runtime in-TCB compromise AFTER the boot extend (the PCR is a boot snapshot), and
does NOT catch a BINARY SWAP — `expectedDefaultArmedD` hashes the box's OWN `/proc/self/exe`, so a
swapped collector derives D from the swapped binary and self-passes. This is a SAME-BOX self-check,
strictly WEAKER than the OFF-BOX relying-party verify that already ships (`scripts/qemu-attest-check.py`
runs the full `attest verify` from a separate machine). Framed honestly: the box cryptographically
proves its quote is genuine + fresh + matches its own boot-extended, self-derived D — NOT that it is
unmodified. The pre-provisioned EK-rooted pin adds this-TPM identity; the structural fallback does not.

## Break-glass

Unchanged from ADR-0021: re-arm enforce, or `systemctl mask` the gate(s) (masking BRICKS the rejoin on
the shipped systemd, so re-arm is the supported path — see `deploy/tailscale-join.md`). On a TPM-less
box the crypto gate is Condition-skipped and only the map-read gate gates; there is nothing to mask.
