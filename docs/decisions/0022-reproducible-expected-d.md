# ADR-0022: Reproducible expected-D — deriving the verifier's expected digest off-box

Status: Accepted
Date: 2026-06-04
Relates to: ADR-0019 (the PCR-14 quote + the digest D), ADR-0020 (EK-rooted AK), ADR-0021 (the posture
gate, whose cryptographic upgrade this unblocks).

## Context

ADR-0019's off-box verify checks the quoted PCR against `H(SHA256(H(0^32 || D)))` for an EXPECTED good
`D`. But where does the verifier get `D`? Today the swtpm harness greps it from the box's OWN collector
journal (`journalctl -u bulkhead-collector | grep 'attest: extended'`). That is CIRCULAR: a tampered
collector logs whatever green `D` it likes and self-passes. EK-rooting (ADR-0020) closed the AK-forgery
half; this closes the other half — the expected `D` must be derived INDEPENDENTLY of the box, from the
known-good collector binary + the expected posture.

Feasibility was proven empirically before designing: the collector build is byte-reproducible. Two
offline host builds are byte-identical, and the actual MEASURED target (the STRIPPED rootfs binary,
== `/proc/self/exe` on the read-only rootfs) reproduces byte-for-byte from the cross output via the
Yocto post-process chain (`objcopy --only-keep-debug` → `--add-gnu-debuglink` with the bare basename
`bulkhead-collector` → `strip`). So a relying party with the source + toolchain reproduces the exact
binary the box measures, and from it computes the exact `D`.

## Decision

1. **One canonical serialization** (`composeDigest`, `src/collector/attest.go`): the digest bytes —
   domain tag `bulkhead-attest-v1`, fixed field order (binary-hash, `enforce_flags` over the sorted
   hook set, tcb `(count, clean)`), 8-byte BE length prefixes, never json — are factored into ONE pure
   function called by BOTH the live `attestDigest` (which reads `/proc/self/exe` + the live maps) AND
   the off-box subcommand. A relying party's expected `D` and the box's extended `D` are therefore
   byte-identical by construction. A golden unit test (`TestComposeDigestGoldenV1`) pins the v1 bytes so
   a refactor drift fails CI instead of silently changing the digest behind the v1 tag.

2. **Off-box `attest expected-d <collector-binary>`** (no TPM, no maps): computes `D =
   composeDigest(sha256(binary), expected default-armed posture, expected tcb)`. The posture is the
   ADR-0018 default-armed expectation — E0(`bpf`)+E2(`socket_connect`) ENFORCE, E1/E3 observe, tcb clean
   with exactly {root, collector, broker} (count 3). It is deliberately NOT "all-armed": E1/E3 are not
   armed by default, so requiring them would compute a `D` no healthy box ever extends. The relying
   party feeds the byte-reproducible stripped binary; the result is the `D` it passes to `attest verify`.

3. **The harness sources D off-box.** `qemu-attest-check.py` now derives `D` via `attest expected-d
   /usr/bin/bulkhead-collector` and uses THAT for every verify; the journal grep is kept ONLY as a
   cross-check (asserting the off-box `D` equals the box's extended `D`). The circularity is broken: the
   verifier no longer trusts the box's own journal.

This unblocks the cryptographic upgrade of the ADR-0021 posture gate (the box self-verifies a fresh-
nonce EK-rooted quote against an off-box-derived expected-`D`) and the fold-into-`D` variant of
audit-HEAD binding.

## Verification

Host `go build`/`vet` + the golden + field-binding unit tests (`composeDigest` byte format pinned; every
input binds; an absent hook == observe so `expected-d` matches the live full vector). QEMU
(`qemu-attest-check.py`, swtpm): the expected-`D` derived OFF-BOX from `/usr/bin/bulkhead-collector` +
the default-armed posture MATCHES the box's extended digest (cross-checked against the journal), and
that off-box `D` drives the full ADR-0019/0020/0021 suite (quote / verify / EK-rooting / gate) — proving
the verifier needs only the known-good binary + posture, not the box's journal. The byte-reproducibility
of the measured binary was proven separately (two identical host builds; the stripped rootfs binary
reproduced via the Yocto objcopy/strip chain).

## Seam

- **The posture is hardcoded to the ADR-0018 default-armed expectation.** `expected-d` computes `D` for
  {E0+E2 enforce, E1/E3 observe, tcb count 3 clean} — the shipped posture. A box deliberately run in a
  different posture would need a different expected-`D`; a `--posture` override is a trivial follow-up,
  deferred until a non-default posture is actually attested.
- **Reproducibility depends on the fixed toolchain + the Yocto post-process.** The measured binary is
  the stripped rootfs artifact; a relying party must reproduce that exact post-process (or pull the
  binary from the signed release rootfs). The `.gnu_debuglink` embeds the bare basename
  `bulkhead-collector` — a wrong filename breaks byte-identity. Confirming the same hash inside the
  released `.swu` bundle's rootfs is a pre-production follow-up.
- **This derives the expected VALUE; it does not itself make anything fail-closed.** The load-bearing
  use (the gate's cryptographic self-verify against this off-box `D`) is ADR-0021's follow-up slice.
