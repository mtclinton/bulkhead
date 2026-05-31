# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead service topology: units, nftables egress floor, fail-closed gate"
HOMEPAGE = "https://github.com/mtclinton/bulkhead"
LICENSE = "AGPL-3.0-only"
LIC_FILES_CHKSUM = "file://LICENSE;md5=eb1e647870add0502f8f010b19de32af"

SRC_URI = "git://github.com/mtclinton/bulkhead.git;protocol=https;branch=main;destsuffix=git"
SRCREV = "b46e34d778b8e5baf2c693e4c61affa3a4734bcd"
S = "${WORKDIR}/git"

inherit systemd allarch

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
	install -d ${D}${systemd_system_unitdir}/bulkhead-router.service.d
	install -m0644 ${OV}/etc/systemd/system/bulkhead-router.service.d/*.conf \
		${D}${systemd_system_unitdir}/bulkhead-router.service.d/

	# nftables default-deny egress floor
	install -Dm0644 ${OV}/etc/nftables.conf ${D}${sysconfdir}/nftables.conf

	# model mount point (filled from the persistent data partition at boot)
	install -d ${D}${localstatedir}/lib/bulkhead/models
}

FILES:${PN} = "\
    ${systemd_system_unitdir} \
    ${sysconfdir}/nftables.conf \
    ${localstatedir}/lib/bulkhead \
"
