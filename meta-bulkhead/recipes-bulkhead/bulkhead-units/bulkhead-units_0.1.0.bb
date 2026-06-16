# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead service topology: units, nftables egress floor, fail-closed gate"
HOMEPAGE = "https://github.com/mtclinton/bulkhead"
LICENSE = "AGPL-3.0-only"
LIC_FILES_CHKSUM = "file://LICENSE;md5=eb1e647870add0502f8f010b19de32af"

SRC_URI = "git://github.com/mtclinton/bulkhead.git;protocol=https;branch=main;destsuffix=git \
           file://bulkhead-collector-data.conf \
           file://bulkhead-broker-data.conf \
           file://bulkhead-router-data.conf \
           file://bulkhead-egress-proxy-data.conf \
           file://bulkhead-provision-mitm-ca.service \
           file://bulkhead-egress-proxy-mitm.conf \
           file://provision-mitm-ca-tpm2-mode.conf \
           file://mitm-cred-tpm2.conf \
           file://bulkhead-seal-audit-key.service \
           file://bulkhead-seal-audit-key \
           file://bulkhead-verify-audit.service \
           file://bulkhead-selftest-verify.conf \
           file://audit-cred-tpm2.conf \
           file://seal-tpm2-mode.conf \
           file://rauc-mark-good-gate.conf"
# Pinned to 0c6c8fc (ADR-0033 io_uring deny + ADR-0034 router-UDS AF_UNIX fix): the overlay carries the
# structural-egress units (bulkhead-egress-proxy.service incl. its StateDirectory/audit base config, the
# bulkhead-agent-confined@ PrivateNetwork jail template, the router UDS, egress-allow.conf). Both agent
# jail templates subtract io_uring_setup/enter/register from their SystemCallFilter (ADR-0033), and the
# router now lists AF_UNIX in RestrictAddressFamilies so it can create its UDS instead of crash-looping
# (without it the confined agent's model leg never existed). The bulkhead-egress-proxy-data.conf drop-in
# (files/) persists the proxy's signed chain on /data + the sealed seed; verify-audit gates the egress chain.
SRCREV = "dd7886f23715a48aa71bff130d024735cba46eed"
S = "${WORKDIR}/git"

inherit systemd allarch

# Yocto-only collector drop-in (redirect the audit log to /data) lives in files/,
# NOT the shared rootfs-overlay (so Buildroot's writable-rootfs path is untouched).
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

# ADR-0028: audit-seed key delivery, chosen at build time. "plain" (default, VM/dev) ships the
# plaintext-on-/data seed via LoadCredential. "tpm2" (bare metal) installs override drop-ins so the
# seal service hardware-seals the seed and every consumer loads it via LoadCredentialEncrypted.
# Set BULKHEAD_SEAL_KEY = "tpm2" in local.conf for a bare-metal build. do_install branches on it.
BULKHEAD_SEAL_KEY ??= "plain"
do_install[vardeps] += "BULKHEAD_SEAL_KEY"

# Files-only recipe; ${S} is the repo root whose Makefile is the Buildroot
# prototype's — keep base_do_configure from running `make clean` against it.
do_configure[noexec] = "1"

OV = "${S}/external/board/bulkhead/rootfs-overlay"

# The units ExecStart these; pull them into any image that installs the topology.
RDEPENDS:${PN} = "bulkhead-router bulkhead-agent bulkhead-collector bulkhead-egress-proxy llama-cpp tailscale nftables"

# Boot order is encoded in the units themselves (firewall -> selftest gate ->
# collector/llama/router; tailscale-up + mounts are ConditionPathExists-guarded).
# tailscaled.service is enabled by the tailscale recipe (it owns that unit).
SYSTEMD_SERVICE:${PN} = "\
    bulkhead-firewall.service \
    bulkhead-selftest.service \
    bulkhead-collector.service \
    bulkhead-egress-proxy.service \
    llama-server.service \
    bulkhead-router.service \
    bulkhead-router-bind.service \
    tailscale-up.service \
    mnt-tsauth.mount \
    var-lib-bulkhead-models.mount \
    bulkhead-broker.socket \
    bulkhead-seal-audit-key.service \
    bulkhead-provision-mitm-ca.service \
    bulkhead-verify-audit.service \
    bulkhead-broker.service \
    bulkhead-enforce.service \
    bulkhead-enforce-egress.service \
    bulkhead-attest.service \
    bulkhead-attest-gate.service \
    bulkhead-attest-selfcheck-gate.service \
"
# ADR-0018 HARDEN-BY-DEFAULT: the shipped image boots ENFORCED. bulkhead-broker.service is
# boot-started (so its cgroup exists for the enforce gate; it still inherits the .socket fd via
# LISTEN_FDS), and bulkhead-enforce.service (E0 = lsm/bpf deny) + bulkhead-enforce-egress.service
# (E2 = per-agent egress) auto-arm. A failed arm degrades to safe observe (enforce_flags-empty =>
# observe by construction), never a brick. Soft-disarm: `systemctl stop bulkhead-enforce[-egress]`.
SYSTEMD_AUTO_ENABLE = "enable"

do_install() {
	install -d ${D}${systemd_system_unitdir}
	install -m0644 ${OV}/etc/systemd/system/*.service ${D}${systemd_system_unitdir}/
	install -m0644 ${OV}/etc/systemd/system/*.mount   ${D}${systemd_system_unitdir}/
	install -m0644 ${OV}/etc/systemd/system/*.slice   ${D}${systemd_system_unitdir}/
	install -m0644 ${OV}/etc/systemd/system/*.socket  ${D}${systemd_system_unitdir}/
	install -d ${D}${systemd_system_unitdir}/bulkhead-router.service.d
	install -m0644 ${OV}/etc/systemd/system/bulkhead-router.service.d/*.conf \
		${D}${systemd_system_unitdir}/bulkhead-router.service.d/

	# Agent jail: per-instance egress drop-ins (the demo agents) + the stub payload.
	for d in ${OV}/etc/systemd/system/bulkhead-agent@*.service.d; do
		dn=$(basename "$d")
		install -d ${D}${systemd_system_unitdir}/$dn
		install -m0644 $d/*.conf ${D}${systemd_system_unitdir}/$dn/
	done
	install -Dm0755 ${OV}/usr/bin/bulkhead-agent-run ${D}${bindir}/bulkhead-agent-run
	# ADR-0031: the gVisor-substrate agent launcher (ExecStart of bulkhead-agent-runsc@.service)
	install -Dm0755 ${OV}/usr/bin/bulkhead-agent-runsc-launch ${D}${bindir}/bulkhead-agent-runsc-launch

	# Yocto-only: persist the collector audit log on /data (RO rootfs -> /var is volatile)
	install -d ${D}${systemd_system_unitdir}/bulkhead-collector.service.d
	install -m0644 ${WORKDIR}/bulkhead-collector-data.conf \
		${D}${systemd_system_unitdir}/bulkhead-collector.service.d/10-data-persistence.conf

	# Yocto-only: persist the broker's signed approval-decision log on /data
	install -d ${D}${systemd_system_unitdir}/bulkhead-broker.service.d
	install -m0644 ${WORKDIR}/bulkhead-broker-data.conf \
		${D}${systemd_system_unitdir}/bulkhead-broker.service.d/10-data-persistence.conf

	# Yocto-only: persist the router's signed routing-decision chain on /data (ADR-0027 seam).
	# The bulkhead-router.service.d/ dir was already created above for the overlay's 11-audit.conf;
	# 12- sorts AFTER it so this drop-in's /data BULKHEAD_AUDIT_DIR override is the one that wins.
	install -m0644 ${WORKDIR}/bulkhead-router-data.conf \
		${D}${systemd_system_unitdir}/bulkhead-router.service.d/12-data-persistence.conf

	# Yocto-only: persist the egress proxy's signed egress-decision chain on /data (ADR-0034)
	install -d ${D}${systemd_system_unitdir}/bulkhead-egress-proxy.service.d
	install -m0644 ${WORKDIR}/bulkhead-egress-proxy-data.conf \
		${D}${systemd_system_unitdir}/bulkhead-egress-proxy.service.d/10-data-persistence.conf
	# ADR-0034 inc2: deliver the re-signing CA as credentials + enable TLS-termination (sorts after 10-)
	install -m0644 ${WORKDIR}/bulkhead-egress-proxy-mitm.conf \
		${D}${systemd_system_unitdir}/bulkhead-egress-proxy.service.d/20-mitm.conf

	# Yocto-only: first-boot TPM sealing of the audit signing seed (ADR-0008)
	install -m0644 ${WORKDIR}/bulkhead-seal-audit-key.service ${D}${systemd_system_unitdir}/
	install -Dm0755 ${WORKDIR}/bulkhead-seal-audit-key ${D}${bindir}/bulkhead-seal-audit-key
	# ADR-0034 inc2: first-boot on-device provisioning of the egress-proxy re-signing CA
	install -m0644 ${WORKDIR}/bulkhead-provision-mitm-ca.service ${D}${systemd_system_unitdir}/

	# Yocto-only: audit-chain verification boot gate (F5) + drop-in folding it into the
	# selftest gate (so a broken/forged chain refuses the boot).
	install -m0644 ${WORKDIR}/bulkhead-verify-audit.service ${D}${systemd_system_unitdir}/
	install -d ${D}${systemd_system_unitdir}/bulkhead-selftest.service.d
	install -m0644 ${WORKDIR}/bulkhead-selftest-verify.conf \
		${D}${systemd_system_unitdir}/bulkhead-selftest.service.d/10-verify-chain.conf

	# ADR-0028: bare-metal tpm2 production wiring (BULKHEAD_SEAL_KEY=tpm2). Coherently switch the
	# seed delivery from plaintext-on-/data (LoadCredential) to a TPM2-sealed cred
	# (LoadCredentialEncrypted) across the seal service + EVERY audit-seed consumer in one place.
	# Default plain (VM/dev) installs none of this, so that path stays byte-for-byte unchanged.
	if [ "${BULKHEAD_SEAL_KEY}" = "tpm2" ]; then
		install -d ${D}${systemd_system_unitdir}/bulkhead-seal-audit-key.service.d
		install -m0644 ${WORKDIR}/seal-tpm2-mode.conf \
			${D}${systemd_system_unitdir}/bulkhead-seal-audit-key.service.d/20-tpm2.conf
		# Same cred override for each consumer; 20- sorts after their base drop-in (10-/12-). The
		# .d dirs for collector/broker/router exist from above; install -d is idempotent for them.
		for svc in bulkhead-collector bulkhead-broker bulkhead-router bulkhead-egress-proxy bulkhead-verify-audit; do
			install -d ${D}${systemd_system_unitdir}/$svc.service.d
			install -m0644 ${WORKDIR}/audit-cred-tpm2.conf \
				${D}${systemd_system_unitdir}/$svc.service.d/20-audit-cred-tpm2.conf
		done
		# ADR-0034 inc2: tpm2-seal the re-signing CA key too. Provision in tpm2 mode (20-tpm2.conf sets
		# BULKHEAD_SEAL_KEY=tpm2 so the CA key is sealed to ca.key.cred, no plaintext), and flip the
		# proxy's CA-KEY credential to the sealed cred (30- sorts after 20-mitm.conf + 20-audit-cred-tpm2.conf;
		# the public ca.crt stays plaintext).
		install -d ${D}${systemd_system_unitdir}/bulkhead-provision-mitm-ca.service.d
		install -m0644 ${WORKDIR}/provision-mitm-ca-tpm2-mode.conf \
			${D}${systemd_system_unitdir}/bulkhead-provision-mitm-ca.service.d/20-tpm2.conf
		install -m0644 ${WORKDIR}/mitm-cred-tpm2.conf \
			${D}${systemd_system_unitdir}/bulkhead-egress-proxy.service.d/30-mitm-cred-tpm2.conf
	fi

	# RAUC-audit fix: gate rauc-mark-good on the bulkhead security gates so a slot that fails
	# selftest/verify-audit is NOT pinned (rolls back). Drop-in over the meta-rauc unit.
	install -d ${D}${systemd_system_unitdir}/rauc-mark-good.service.d
	install -m0644 ${WORKDIR}/rauc-mark-good-gate.conf \
		${D}${systemd_system_unitdir}/rauc-mark-good.service.d/10-bulkhead-gate.conf

	# nftables default-deny egress floor
	install -Dm0644 ${OV}/etc/nftables.conf ${D}${sysconfdir}/nftables.conf

	# ADR-0034: the egress-proxy allowlist (governs the bulkhead-agent-confined@ class only)
	install -Dm0644 ${OV}/etc/bulkhead/egress-allow.conf ${D}${sysconfdir}/bulkhead/egress-allow.conf

	# model mount point (filled from the persistent data partition at boot)
	install -d ${D}${localstatedir}/lib/bulkhead/models
}

FILES:${PN} = "\
    ${systemd_system_unitdir} \
    ${bindir}/bulkhead-agent-run \
    ${bindir}/bulkhead-agent-runsc-launch \
    ${bindir}/bulkhead-seal-audit-key \
    ${sysconfdir}/nftables.conf \
    ${sysconfdir}/bulkhead \
    ${localstatedir}/lib/bulkhead \
"
