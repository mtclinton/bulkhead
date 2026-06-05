# ADR-0025: bind the signed audit-chain HEADs into the attestation quote

Status: Accepted
Date: 2026-06-04
Relates to: ADR-0017 (signed audit chains), ADR-0019 (the quote: fresh-nonce AK-signed TPM2_Quote of
the enforcing-posture PCR), ADR-0022 (reproducible off-box expected-D), ADR-0023 (on-box self-check),
ADR-0024 (composed-system sweep). Completes the attestation line: one quote now proves posture AND
authority history.

## Context

ADR-0019 binds only the verifier nonce into the quote (`QualifyingData == nonce`): the proof answers
"is the box in the expected enforcing posture, right now, freshly?" It says nothing about the box's
AUTHORITY HISTORY — the three ADR-0017 signed chains (collector provenance, control, broker) record
every enforcement decision and every delegated grant, but a relying party could only audit them
OUT-OF-BAND, and a box could present a quote (good posture) while having quietly rewound, forked, or
truncated a chain to erase a record. Posture and history were two separate trust questions.

## Decision

The quote's `QualifyingData` (ExtraData) is now `quoteExtraData(nonce, H_collector, H_control,
H_broker)` — a domain-separated (`"bulkhead-attest-qd-v1"`), length-prefixed SHA-256 over the verifier
nonce and the three chains' current HEADs (last record hash), in a FIXED order. (The 32+3×32 = 128 bytes
overflow the ~64-byte TPM2B_DATA cap, so a hash is required, not concatenation.) A genesis/empty/
unreadable chain HEAD maps to 32 deterministic zero bytes (the openAuditLog genesis), so a fresh box has
a well-defined reproducible binding. One `TPM2_Quote` now cryptographically binds, under the AK and the
fresh nonce, BOTH the enforcing posture (PCR 14) AND the exact chain state.

- **doAttestQuote** reads the three HEADs from DISK via `lastChainHash` and computes the binding. No
  lock: each `append()` is a single `write()`+`fsync` and every chain is single-writer, so a reader
  never sees a torn line; a concurrent append advancing a HEAD between the three reads is benign (the
  quote binds whatever was on disk; the verifier checks its own prior-observed expected). The envelope
  also SHIPS the bound HEADs (`head_*_hex`) for operator transparency — but they are NOT load-bearing.
- **verifyEnvelopeChecks** check (b) is now a PURE `ExtraData == expectedExtraData` equality; the caller
  precomputes `expectedExtraData` via the one `quoteExtraData` helper (single source of truth).
- **cmdAttestVerify** (off-box) takes the relying party's EXPECTED HEADs out-of-band (a 6th
  `collHex:ctrlHex:brokerHex` / `@file` arg), exactly like the nonce and the AK pin — NEVER the
  envelope's attacker-suppliable claim. A box that rewound/forked/truncated a chain below the expected
  cannot produce a quote whose ExtraData matches, so verify fails closed.
- **doAttestSelfCheck** (on-box) recomputes the expected from the HEADs the quote CLAIMS (shipped in the
  envelope by the same in-process quote), avoiding a disk-reread TOCTOU; its HEAD role is binding
  INTEGRITY (the quote is well-formed over its claimed state), NOT rewind detection.
- New **`attest heads`** verb: prints the three HEADs as `collHex:ctrlHex:brokerHex` (genesis ⇒ 64
  zeros) — the relying party's prior-observed (TOFU) capture, and an off-box file read (no TPM/socket).

## Verification

`go build`/`vet`/`test`/`test -race` green. New unit tests: a pinned golden vector for `quoteExtraData`
(`61ea19…6411`); genesis-nil == explicit-32-zero; every field binds AND the three HEAD slots do not
alias (swap collector↔control changes the digest); domain-separation (never equals the raw nonce nor a
bare SHA-256(nonce), so it can't collide with an ADR-0019 quote); `parseExpectedHeads` round-trip +
malformed-input rejection. Live swtpm (`make verify-attest`): `attest heads` reads three well-formed
HEADs; the POSITIVE verify (INDEPENDENT `attest heads` read, not the envelope claim) is OK; a new
NEGATIVE — verify FAILS CLOSED against a one-byte-tampered expected HEAD (the no-rewind teeth) — plus
the existing tamper-D / replay-nonce / wrong-AK negatives still fail closed, and the self-check still
passes (now reporting "chain HEADs bound").

## Seam

- **What it proves:** at quote time (fresh nonce, TPM-signed) the chains were AT these HEADs. The
  no-rewind guarantee is RELATIVE to the relying party's prior observation (TOFU): a rewind/fork/
  truncation BELOW the expected HEAD fails closed. It does NOT prove continuous history BETWEEN quotes
  (a box could advance then rewind between two unobserved quotes), and the on-box self-check gains no
  rewind teeth (it binds its own claimed HEADs — those teeth are the off-box relying party's, which
  supplies the expected). It does not authenticate the chains' CONTENTS beyond their head hash — that is
  `verify-audit`'s job on the shipped logs.
- **The broker chain** lives in the broker's separate `$BULKHEAD_AUDIT_DIR` (= the collector base +
  `-broker` in every shipped config); the collector reads its file directly. `brokerAuditDir()` encodes
  that coupling with a `$BULKHEAD_BROKER_AUDIT_DIR` override if the two are ever decoupled.
