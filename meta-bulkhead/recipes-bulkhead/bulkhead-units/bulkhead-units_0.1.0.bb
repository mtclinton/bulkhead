# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead service topology: units, nftables egress floor, fail-closed gate"
HOMEPAGE = "https://github.com/mtclinton/bulkhead"
LICENSE = "AGPL-3.0-only"
LIC_FILES_CHKSUM = "file://LICENSE;md5=eb1e647870add0502f8f010b19de32af"

SRC_URI = "git://github.com/mtclinton/bulkhead.git;protocol=https;branch=main;destsuffix=git \
           file://bulkhead-collector-data.conf"
SRCREV = "4a27630185addd28db3e173449d25e6fbca31b54"
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
"
SYSTEMD_AUTO_ENABLE = "enable"

do_install() {
	install -d ${D}${systemd_system_unitdir}
	install -m0644 ${OV}/etc/systemd/system/*.service ${D}${systemd_system_unitdir}/
	install -m0644 ${OV}/etc/systemd/system/*.mount   ${D}${systemd_system_unitdir}/
	install -m0644 ${OV}/etc/systemd/system/*.slice   ${D}${systemd_system_unitdir}/
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

	# nftables default-deny egress floor
	install -Dm0644 ${OV}/etc/nftables.conf ${D}${sysconfdir}/nftables.conf

	# model mount point (filled from the persistent data partition at boot)
	install -d ${D}${localstatedir}/lib/bulkhead/models
}

FILES:${PN} = "\
    ${systemd_system_unitdir} \
    ${bindir}/bulkhead-agent-run \
    ${sysconfdir}/nftables.conf \
    ${localstatedir}/lib/bulkhead \
"
