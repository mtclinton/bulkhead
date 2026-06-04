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
   - **Structural fallback** (no pin file): verify against the quote's OWN AK — which is attacker-
     suppliable, so it does NOT authenticate the TPM and makes NO identity assertion (a tampered
     collector forges the whole envelope in software and passes — exactly why the OFF-BOX verify
     requires an out-of-band pin). ASSUMING an honest collector it adds freshness (our own nonce) +
     the immutable-boot-PCR == expected-D over the map read; against a tampered collector it is
     defeated as easily as the map read. Honest by construction (the detail string reports
     `identity=structural-fallback`); this is the shipped default under qemu (no `/data` pin).

3. **A SECOND unit, AUGMENT not REPLACE** (`bulkhead-attest-selfcheck-gate.service`). A crypto gate
   needs a TPM, so it `ConditionPathExists=/dev/tpmrm0` — on a legitimately TPM-LESS but enforcing box
   it cleanly SKIPS (systemd treats a skipped `Requires=` dependency as satisfied). It is LAYERED on
   top of the UNCONDITIONAL ADR-0021 map-read gate (conditioned on the collector BINARY, not the TPM),
   which keeps gating the no-TPM box. `tailscale-up.service` `Requires=+After=` BOTH gates. Replacing
   the map read with a crypto-only gate would FAIL-OPEN the no-TPM box — the regression this avoids.
   The selfcheck-gate orders `After=bulkhead-attest.service` so PCR 14 already holds the boot extend.

## What it proves — and explicitly does NOT

PCR 14 holds the BOOT `attest extend` of D (one-way, extend-only) and is IMMUTABLE after boot. A pass
proves a FRESH (nonce), exactly-PCR-14 quote whose PCR == H(0^32 || expected-default-armed-D) — the box
BOOTED in the expected default-armed posture. Because the boot PCR cannot change, this CATCHES a
NEVER-ARMED boot AND a runtime MAP-FLIP (a box that booted observe and later flips the live maps to
fake-armed: the ADR-0021 map read passes, but the immutable boot PCR does not) — NEITHER of which the
map read catches.

**Strength depends on the pin.** WITH the pre-provisioned EK-rooted pin the quote's AK is matched to a
KNOWN TPM key, so the quote is AUTHENTICATED as genuine-TPM and a SOFTWARE-FORGED quote is rejected. In
the STRUCTURAL FALLBACK (no pin — the shipped default under qemu) the verifying AK is the quote's own,
which is attacker-suppliable: a TAMPERED collector forges the whole envelope in software (sets magic,
self-signs, `PCRDigest = H(H(0||expD))`) and passes — so the fallback does NOT authenticate the TPM and
does NOT catch a tampered collector / software-forged quote. Against a tampered collector it is defeated
as easily as the map read it augments; its value (over the map read) is freshness + the immutable boot
PCR, ASSUMING an honest collector.

In all cases it does NOT catch a runtime in-TCB compromise AFTER the boot extend (the PCR is a boot
snapshot), and does NOT catch a BINARY SWAP — `expectedDefaultArmedD` hashes the box's OWN
`/proc/self/exe`. This is a SAME-BOX self-check, strictly WEAKER than the OFF-BOX relying-party verify
that already ships (`scripts/qemu-attest-check.py` runs the full `attest verify` from a separate
machine, with an out-of-band pin). The pre-provisioned EK-rooted pin adds this-TPM identity + genuine-
TPM authentication; the structural fallback does neither.

## Break-glass

Unchanged from ADR-0021: re-arm enforce, or `systemctl mask` the gate(s) (masking BRICKS the rejoin on
the shipped systemd, so re-arm is the supported path — see `deploy/tailscale-join.md`). On a TPM-less
box the crypto gate is Condition-skipped and only the map-read gate gates; there is nothing to mask.
