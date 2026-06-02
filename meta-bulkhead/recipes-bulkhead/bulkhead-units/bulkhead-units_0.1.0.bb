# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead service topology: units, nftables egress floor, fail-closed gate"
HOMEPAGE = "https://github.com/mtclinton/bulkhead"
LICENSE = "AGPL-3.0-only"
LIC_FILES_CHKSUM = "file://LICENSE;md5=eb1e647870add0502f8f010b19de32af"

SRC_URI = "git://github.com/mtclinton/bulkhead.git;protocol=https;branch=main;destsuffix=git \
           file://bulkhead-collector-data.conf \
           file://bulkhead-broker-data.conf \
           file://bulkhead-seal-audit-key.service \
           file://bulkhead-seal-audit-key \
           file://bulkhead-verify-audit.service \
           file://bulkhead-selftest-verify.conf"
SRCREV = "d2e7b2d109a8a005c23b1ec180b1c5bc0b920e3f"
S = "${WORKDIR}/git"

inherit systemd allarch

# Yocto-only collector drop-in (redirect the audit log to /data) lives in files/,
# NOT the shared rootfs-overlay (so Buildroot's writable-rootfs path is untouched).
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

# Files-only recipe; ${S} is the repo root whose Makefile is the Buildroot
# prototype's — keep base_do_configure from running `make clean` against it.
do_configure[noexec] = "1"

OV = "${S}/external/board/bulkhead/rootfs-overlay"

# The units ExecStart these; pull them into any image that installs the topology.
RDEPENDS:${PN} = "bulkhead-router bulkhead-collector llama-cpp tailscale nftables"

# Boot order is encoded in the units themselves (firewall -> selftest gate ->
# collector/llama/router; tailscale-up + mounts are ConditionPathExists-guarded).
# tailscaled.service is enabled by the tailscale recipe (it owns that unit).
SYSTEMD_SERVICE:${PN} = "\
    bulkhead-firewall.service \
    bulkhead-selftest.service \
    bulkhead-collector.service \
    llama-server.service \
    bulkhead-router.service \
    bulkhead-router-bind.service \
    tailscale-up.service \
    mnt-tsauth.mount \
    var-lib-bulkhead-models.mount \
    bulkhead-broker.socket \
    bulkhead-seal-audit-key.service \
    bulkhead-verify-audit.service \
"
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

	# Yocto-only: persist the collector audit log on /data (RO rootfs -> /var is volatile)
	install -d ${D}${systemd_system_unitdir}/bulkhead-collector.service.d
	install -m0644 ${WORKDIR}/bulkhead-collector-data.conf \
		${D}${systemd_system_unitdir}/bulkhead-collector.service.d/10-data-persistence.conf

	# Yocto-only: persist the broker's signed approval-decision log on /data
	install -d ${D}${systemd_system_unitdir}/bulkhead-broker.service.d
	install -m0644 ${WORKDIR}/bulkhead-broker-data.conf \
		${D}${systemd_system_unitdir}/bulkhead-broker.service.d/10-data-persistence.conf

	# Yocto-only: first-boot TPM sealing of the audit signing seed (ADR-0008)
	install -m0644 ${WORKDIR}/bulkhead-seal-audit-key.service ${D}${systemd_system_unitdir}/
	install -Dm0755 ${WORKDIR}/bulkhead-seal-audit-key ${D}${bindir}/bulkhead-seal-audit-key

	# Yocto-only: audit-chain verification boot gate (F5) + drop-in folding it into the
	# selftest gate (so a broken/forged chain refuses the boot).
	install -m0644 ${WORKDIR}/bulkhead-verify-audit.service ${D}${systemd_system_unitdir}/
	install -d ${D}${systemd_system_unitdir}/bulkhead-selftest.service.d
	install -m0644 ${WORKDIR}/bulkhead-selftest-verify.conf \
		${D}${systemd_system_unitdir}/bulkhead-selftest.service.d/10-verify-chain.conf

	# nftables default-deny egress floor
	install -Dm0644 ${OV}/etc/nftables.conf ${D}${sysconfdir}/nftables.conf

	# model mount point (filled from the persistent data partition at boot)
	install -d ${D}${localstatedir}/lib/bulkhead/models
}

FILES:${PN} = "\
    ${systemd_system_unitdir} \
    ${bindir}/bulkhead-agent-run \
    ${bindir}/bulkhead-seal-audit-key \
    ${sysconfdir}/nftables.conf \
    ${localstatedir}/lib/bulkhead \
"
