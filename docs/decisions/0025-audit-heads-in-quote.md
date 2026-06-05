# ADR-0025: bind the signed audit-chain HEADs into the attestation quote

Status: Accepted
Date: 2026-06-04
Relates to: ADR-0017 (signed audit chains), ADR-0019 (the quote: fresh-nonce AK-signed TPM2_Quote of
the enforcing-posture PCR), ADR-0022 (reproducible off-box expected-D), ADR-0023 (on-box self-check),
ADR-0024 (composed-system sweep). Extends the attestation line: the quote now also commits, non-
repudiably, to the box's audit-chain state.

## Context

ADR-0019 binds only the verifier nonce into the quote (`QualifyingData == nonce`): the proof answers
"is the box in the expected enforcing posture, right now, freshly?" It says nothing about the box's
authority history — the three ADR-0017 signed chains (collector provenance, control, broker) record
every enforcement decision and every delegated grant, but they could only be audited OUT-OF-BAND, with
nothing tying a given quote to a specific, attested chain state.

A first cut tried to make the verifier supply its OWN expected chain HEADs (TOFU) and fail closed on a
mismatch. **Live swtpm testing falsified that model:** the collector provenance chain appends on EVERY
enforcement decision (allowed/denied/would-deny from the BPF ringbuf), and the control chain on every
operator/agent authority change — so a chain's HEAD advances between ANY independent observation and the
quote. Exact-match against an independently-captured HEAD can therefore never hold for a live chain (the
positive verify failed in qemu for exactly this reason). Unlike the nonce, the verifier cannot know a
live chain's HEAD independently.

## Decision

The quote's `QualifyingData` (ExtraData) is `quoteExtraData(nonce, H_collector, H_control, H_broker)` —
a domain-separated (`"bulkhead-attest-qd-v1"`), length-prefixed SHA-256 over the verifier nonce and the
three chains' current HEADs, FIXED order, genesis/empty/unreadable ⇒ 32 zero bytes. (32+3×32 = 128 bytes
overflow the ~64-byte TPM2B_DATA cap, so a hash is required.) The HEADs travel in the envelope
(`head_*_hex`), and the verifier **recomputes the ExtraData over those reported HEADs**. This makes the
box's reported audit-chain state, under the fresh nonce + TPM signature:

- **non-repudiable** — the box committed to exactly these HEADs, TPM-signed;
- **replay-proof** — the verifier's fresh nonce is folded in, so an old quote fails;
- **tamper-evident** — altering any `head_*_hex` after the quote changes the recomputed ExtraData and
  fails verify closed; a MITM/box cannot restate the HEADs a quote committed to.

The nonce stays the verifier's OWN (freshness); the HEADs necessarily come from the box's report (a live
chain advances), made trustworthy by the binding. **No-rewind is NOT proven by the quote alone** — it is
a SEPARATE relying-party step: run `verify-audit` on the box's shipped chain logs (hash continuity, incl.
the ADR-0017 cross-boot link), confirm each log's tip == the now-non-repudiable bound HEAD, and confirm
it has not regressed below a prior observation. The quote makes the reported HEADs unforgeable; verify-
audit + the prior observation turn that into a rewind/fork verdict.

- **doAttestQuote** reads the three HEADs from DISK via `lastChainHash` (single-writer + single
  `write()`+`fsync` per record ⇒ no torn read, no lock) and ships them in the envelope.
- **verifyEnvelopeChecks** check (b) recomputes `quoteExtraData(nonce, envHeads(env))` and compares —
  one helper is the single source of truth for quote, off-box verify, and on-box self-check.
- **doAttestSelfCheck** verifies over its own reported HEADs (integrity binding; no rewind teeth — that
  is the off-box relying party's job).
- New **`attest heads`** verb prints the live HEADs (`collHex:ctrlHex:brokerHex`) for the relying
  party's prior-observation capture and the live-log cross-check.

## Verification

`go build`/`vet`/`test`/`test -race` green. Unit tests: a pinned golden vector for `quoteExtraData`
(`61ea19…6411`); genesis-nil == explicit-32-zero; every field binds AND the three HEAD slots do not
alias; domain-separation (never equals the raw nonce nor a bare SHA-256(nonce)); `envHeads` decode +
tamper-evidence (a changed reported HEAD changes the binding; an empty field binds as genesis zeros).
Live swtpm (`make verify-attest`): `attest heads` well-formed; the broker chain file exists at the
derived `brokerAuditDir`; the quote's REPORTED control HEAD == the live control HEAD (the box bound its
real state); the positive verify is OK; NEGATIVE 4 — verify FAILS CLOSED when a reported `head_*_hex` is
altered (tamper-evidence) — plus the existing tamper-D / replay-nonce / wrong-AK negatives still fail
closed and the self-check still passes ("chain HEADs bound").

## Seam

- **What the quote proves:** a non-repudiable, replay-proof, tamper-evident commitment to the box's
  reported chain HEADs at quote time. It does NOT, by itself, prove no-rewind/no-fork (a malicious box
  can bind and report an older HEAD) — that requires the SEPARATE verify-audit step on the shipped logs
  + a prior observation. The high-rate collector provenance HEAD is bound but cannot be cross-checked
  against an independent capture (it advances continuously); the slower control/broker HEADs can.
- **The broker chain** lives in the broker's separate `$BULKHEAD_AUDIT_DIR` (= the collector base +
  `-broker` in every shipped config); `brokerAuditDir()` encodes that coupling with a
  `$BULKHEAD_BROKER_AUDIT_DIR` override. A genesis broker HEAD (no delegation yet) is an empty chain,
  not a mis-resolved path — the live harness asserts the broker chain file exists at the derived path.
- **Future work:** fold the verify-audit continuity + tip-match + no-regression check into the relying-
  party flow so a single command renders the full rewind/fork verdict.
