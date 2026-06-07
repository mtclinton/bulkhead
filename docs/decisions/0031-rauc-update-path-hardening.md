# ADR-0031: RAUC A/B update-path hardening — close the rollback axis

Status: Accepted
Date: 2026-06-07
Relates to: ADR-0003 (Yocto production + RAUC A/B verity updates — the capability this hardens), the
`verify-rauc` live test (the A/B install + rollback check this extends). Closes the HIGH + supporting
findings of the 2026-06-07 RAUC update-path adversarial audit.

## Context

RAUC A/B atomic updates are the persistent-compromise surface: a bundle that installs is a rootfs that
survives reboots. An adversarial audit found the INSTALL axis sound — no unsigned/wrong-key bundle can
install, no bundle can write the running/rescue slot, and the verify-audit gate is not bypassed (signature
+ CA-keyring verification gate every install; the inactive-slot invariant and rescue immutability are
confirmed; `boot-gpt-switch` is region-fenced; the grubenv-tamper family all reduce to post-compromise
amplifiers). The ROLLBACK axis was open, plus two supporting gaps:

1. **Rollback defeated (HIGH).** Upstream `rauc-mark-good.service` fires `rauc status mark-good` after
   `boot-complete.target`, which `Requires=` ONLY `sysinit.target` (`systemd-boot-check-no-failures` is
   disabled by preset and meta-bulkhead re-coupled nothing). So a slot that merely boots to sysinit is
   PINNED (`_TRY=0`) even if `bulkhead-selftest` / `bulkhead-verify-audit` FAILED — the A/B health-rollback
   the design exists to provide was reduced to "catches kernel/sysinit panic only." A correctly-signed-but
   -malicious bundle, or any update that boots but trips the audit gate, would never roll back.
2. **No downgrade protection (HIGH).** An old, still-validly-signed bundle reinstalls a known-vulnerable
   rootfs (a patched CVE replayed, surviving reboots). The bundle `version=` was also the frozen meta-rauc
   default `1.0`, so no `min-bundle-version` gate had usable input.
3. **Keyring build-hygiene (low).** The `BULKHEAD_PRODUCTION` gate validated `IMAGE_FEATURES` but not the
   RAUC keyring; a missing `BULKHEAD_RAUC_KEYDIR` only warns, then ships meta-rauc's dummy stub → the box
   can verify NO bundle (fail-closed brick) and the production gate rubber-stamps it.

## Decision

1. **Couple `rauc-mark-good` to the bulkhead security gates** (not the blunt `systemd-boot-check-no
   -failures`, which would also roll back on an unrelated optional-service failure). A drop-in
   (`rauc-mark-good.service.d/10-bulkhead-gate.conf`, shipped by `bulkhead-units`) adds
   `Requires=/After= bulkhead-selftest.service bulkhead-verify-audit.service`, so mark-good runs ONLY when
   the gates passed; a gate failure leaves `_TRY=1` and the next reboot rolls back to the prior good slot.
2. **Downgrade floor.** `bulkhead-bundle.bb` sets a real semver `RAUC_BUNDLE_VERSION = "${DISTRO_VERSION}"`
   (was the frozen `1.0`), and `system.conf` sets `min-bundle-version=0.1.0`. rauc refuses any bundle below
   the floor (`check_version_limits`: install proceeds iff `min <= version`, so the current release still
   installs). Production raises the floor as old releases age out.
3. **Keyring production gate.** The `BULKHEAD_PRODUCTION` `python()` now `bb.fatal`s unless
   `BULKHEAD_RAUC_KEYDIR/ca.cert.pem` exists and is a real certificate — a misconfigured production build
   refuses to ship a stub/missing trust anchor.

## Verification

- **Rollback gate + happy path (live, `verify-rauc`):** the extended check boots A → installs the bundle
  into B → reboots into B → `mark-bad` → rolls back to A, all GREEN, AND asserts `systemctl show
  rauc-mark-good` lists both bulkhead gates (the coupling is active) without breaking the normal A/B switch.
  A non-bundle blob is rejected (rauc verifies before writing a slot).
- **Downgrade (config):** `min-bundle-version` ships in the image and the valid current bundle installs
  (floor non-blocking for the current release); the reject-older semantics are rauc's upstream-tested
  `check_version_limits` (`min <= version`), activated by the config. (A live reject-older leg was dropped:
  busybox lacks `dd conv=notrunc` and `rauc --confopt` did not apply the override in this harness — over
  -testing rauc's own enforcement for disproportionate iteration cost.)
- **Keyring gate (parse):** a `BULKHEAD_PRODUCTION=1` parse fatals when the keyring is absent and passes
  with the real CA. All in `meta-bulkhead/` (a local Yocto layer), so no SRCREV re-pin.

## Seam (audited, deliberately deferred)

- **No CRL / signer-CN pinning** (info): chain trust with CRL off matches rauc's default; a leaked HSM
  signer can't be revoked on-device. On-device CRL delivery to fielded appliances is itself hard — accept
  or harden later (`check-crl=true` + a refresh path, or pin the signer CN).
- **Runtime rootfs has no dm-verity** (low): the signed tar.bz2 is unpacked into a plain (read-only-mounted)
  ext4; verity authenticates the BUNDLE at install, not the booted root. ADR-0003's "immutable, authenticated
  rootfs" is only partially delivered — ship a verity-image rootfs with a roothash on the cmdline, or tighten
  the framing.
- **PCR-7 seed-escrow runbook** (ops): a firmware/Secure-Boot/TPM-RMA change perturbs PCR 7 and brings every
  affected box down until the audit seed is restored — provision a seed-escrow/restore runbook (and consider
  auto-reseal after an authenticated firmware update) before bare-metal fleet deployment.
- **True no-downgrade-below-installed** would need a `RAUC_BUNDLE_HOOKS` install-check comparing to the
  running version; the static `min-bundle-version` floor is the first, standard step.
