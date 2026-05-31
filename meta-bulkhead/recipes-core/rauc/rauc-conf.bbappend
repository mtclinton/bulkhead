# SPDX-License-Identifier: AGPL-3.0-only
# Install the bulkhead device keyring (ca.cert.pem) from an off-repo directory,
# replacing meta-rauc's dummy stub so `rauc install` verifies bundles signed by our
# CA. BULKHEAD_RAUC_KEYDIR (set in build-local local.conf) must contain a file named
# ca.cert.pem; rauc-conf's default relative fetch `file://ca.cert.pem` then resolves
# to ours (copied flat into WORKDIR) and installs to /etc/rauc/ca.cert.pem, matching
# system.conf's [keyring] path=ca.cert.pem. The cert/key never enter the repo
# (.gitignore blocks *.pem); production points BULKHEAD_RAUC_KEYDIR at the real CA
# trust anchor (PKCS#11/HSM-backed signing key stays off-device).
FILESEXTRAPATHS:prepend := "${BULKHEAD_RAUC_KEYDIR}:"
