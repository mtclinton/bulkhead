# ADR-0020: EK-cert credential-activation — rooting the attestation AK in the TPM

Status: Accepted
Date: 2026-06-04
Relates to: ADR-0008 (TPM-sealed audit seed), ADR-0016 (the collector control socket), ADR-0019
(remote attestation — the AK pin this slice roots).

## Context

ADR-0019 makes the enforcing TCB remotely PROVABLE: a fresh-nonce AK-signed `TPM2_Quote` an off-box
verifier checks against a PINNED AK. But that pin is blind TOFU — it proves the quote came from SOME
TPM holding that AK, not that the AK belongs to THE expected box's genuine TPM. A relying party that
records the AK on first contact cannot, by the quote alone, tell a genuine box from an attacker who
stood up their OWN (real) TPM and enrolled its AK. Credential-activation closes that gap: it
cryptographically binds the AK to the box's Endorsement Key, which on bare metal chains to a
TPM-manufacturer CA — so the pin becomes "this AK is loaded in the genuine TPM that owns this EK".

Feasibility was confirmed against the vendored code first: `go-tpm` v0.9.8 vendors every primitive
(`CreateCredential` = MakeCredential without a TPM, `ActivateCredential`, `ECCEKTemplate`,
`ImportEncapsulationKey`, `PolicySession`/`PolicySecret`, `NVReadPublic`/`NVRead`), the swtpm harness
provisions an EK cert (`run-qemu-tpm.sh --create-ek-cert`), and the off-box round-trip
(`ImportEncapsulationKey`→`CreateCredential`) was host-tested before any QEMU boot.

## Decision

Standard TPM remote-attestation enrollment, slotted into the ADR-0016 control socket + the ADR-0019
off-box verify discipline. Four steps, two control round-trips with the verifier between them:

1. **`attest ek`** (on-box; control verb `ATTEST-EK`, runs in the collector/TCB under `tpmMu`,
   operator-gated uid-0 + non-agent like `ATTEST-QUOTE`): `CreatePrimary(Endorsement, ECCEKTemplate)`
   → the EK; `attestAK()` → the SAME owner AK the quote uses; best-effort NV-read the X.509 EK cert
   (probe `0x01c0000a`/`0x01c00016`/`0x01c00002`). Emits `enrollRequest{ek_pub_tpmt, ek_cert_der,
   ek_nv_index, ak_pub_der, ak_pub_tpmt, ak_name}`.

2. **`attest make-credential <request> <secret-out> [ek-ca-pem|@file]`** (OFF-BOX, no TPM):
   RECOMPUTE the AK Name from `ak_pub_tpmt` and reject any request whose claimed `ak_name` differs;
   assert `tpmtECCToPKIX(ak_pub_tpmt) == ak_pub_der` (the key challenged == the key pinned); (bare
   metal) validate `ek_cert_der` chains to the supplied EK-CA root AND cert-pub == EK-pub; pick a
   fresh 32-byte secret; `ImportEncapsulationKey(EK)` → `CreateCredential` → a challenge bound to the
   AK Name and encapsulated to the EK. The secret is held verifier-private — it is the per-round
   replay defense and is NEVER sent to the box.

3. **`attest activate <challenge>`** (on-box; control verb `ATTEST-ACTIVATE`, collector/TCB):
   re-derive EK + AK; satisfy the EK's `AuthPolicy` (a fresh `PolicySession` running
   `TPM2_PolicySecret(RH_ENDORSEMENT)`, rebuilt per `tpmRetry` attempt because the session is
   consumed); `ActivateCredential(AK, EK, challenge)` → the recovered secret.

4. **`attest enroll-verify <response> <secret> <request> <out-pin>`** (OFF-BOX): the recovered secret
   must bytewise-equal the challenge secret. A match proves the AK is loaded in the genuine TPM that
   owns the EK — write its PKIX as the now-EK-ROOTED pin. Thereafter `attest verify … @<pin>` is
   byte-identical to ADR-0019.

**The AK template is UNCHANGED** (ECDSA-P256 restricted-sign, Owner hierarchy, FIXED template).
Credential-activation binds by NAME, which is independent of the parent hierarchy, so the EK and AK
need not share a hierarchy for the same-TPM proof; the enrolled pin is therefore byte-identical to the
quote AK and the ADR-0019 verify + harness are regression-free. The verifier's discipline — recompute
the Name, bind the wrap to it, and assert the challenged key == the pinned key — stops a tampered box
from pinning one key while proving possession of another.

## Verification

Host `go build`/`vet`/`test` (incl. the offline `-mod=vendor GOPROXY=off` recipe build) and an off-box
round-trip check of `ImportEncapsulationKey`→`CreateCredential`→`enroll-verify`. QEMU
(`scripts/qemu-attest-check.py` + `make verify-attest`, swtpm): the existing ADR-0019 7+3 checks stay
byte-identical, then EK-rooting — (8) `attest ek`, enrolled AK == quote AK; (9) off-box
`make-credential`; (10) on-box `activate` → `enroll-verify` OK → EK-rooted pin; (11) the pin is drop-in
for the quote verify. THREE negatives fail closed: **N1** fabricated EK (a foreign EK can't decrypt →
`activate` fails — the secret returns ONLY from the genuine EK), **N2** wrong-AK-Name (loaded AK's Name
!= wrapped → `TPM_RC_INTEGRITY`), **N3** forged request (verifier rejects claimed `ak_name` !=
recomputed Name). No new deps; no change to the verified E0–E3 object, the signed chains, or the
ADR-0019 quote/verify path.

## Seam

HONEST LIMITS, deferred to bare metal (the same split ADR-0008/0019 document):

- **swtpm EK cert is self-signed dev PKI.** This proves LIVE the MakeCredential/ActivateCredential
  MECHANISM end-to-end AND the EK-BINDING of the AK (the secret returns only because the genuine TPM
  owning this EK also holds the AK of the wrapped Name; both the fabricated-EK and wrong-Name cases
  fail closed). It does NOT prove under qemu that the EK belongs to a specific GENUINE HARDWARE box —
  that needs validating the EK cert chain to a manufacturer CA root (Infineon/Nuvoton/STM), bare-metal
  only. The `make-credential` chain-validation + cert-pub==EK-pub code path is present but UNEXERCISED
  under swtpm (no trust anchor passed → NOTE + skip). Equally honest: swtpm is itself a software TPM,
  so even a perfect chain here attests "a software TPM" — the silicon-genuineness link is the part the
  dev environment structurally cannot demonstrate.
- **AK ↔ sealed-seed binding deferred.** Binding the AK to the ADR-0008 sealed audit seed (so a box
  that can't unseal yields neither a valid audit chain NOR a recognizable AK — one TPM-rooted
  identity) is an audit-key ROTATION touching a different trust root: it would change the audit pubkey
  and break `verify-audit` against existing chains + the `audit-pub.txt` export unless the pubkey/domain
  version is bumped and rollover documented. Deferred to its own ADR with that rotation story, rather
  than entangling two independently-versioned trust roots in this slice.
- **EK endorsement auth assumed empty.** `PolicySecret(RH_ENDORSEMENT)` uses empty endorsement auth
  (the swtpm default); a provisioned non-empty EH auth needs an `AuthOption` carrying it — a
  documented bare-metal footgun, out of swtpm scope.
