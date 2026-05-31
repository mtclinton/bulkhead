# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "Tailscale (official static binaries)"
HOMEPAGE = "https://tailscale.com"
LICENSE = "BSD-3-Clause"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/BSD-3-Clause;md5=550794465ba0ec5312d6919e203a55f9"

# Prebuilt static amd64 binaries (same artifact as the v1 prototype).
SRC_URI = "https://pkgs.tailscale.com/stable/tailscale_${PV}_amd64.tgz;sha256sum=e6c08a8ee7e63e69aaf1b62ecd12672b3883fbcd2a176bf6cfa42a15fdce0b6b"
S = "${WORKDIR}/tailscale_${PV}_amd64"

COMPATIBLE_MACHINE = "qemux86-64"
# Prebuilt vendor binaries: skip the source/arch/strip QA that assumes we built them.
INSANE_SKIP:${PN} += "already-stripped ldflags"

inherit systemd
SYSTEMD_SERVICE:${PN} = "tailscaled.service"
SYSTEMD_AUTO_ENABLE = "enable"

do_install() {
	install -Dm0755 ${S}/tailscaled ${D}${sbindir}/tailscaled
	install -Dm0755 ${S}/tailscale  ${D}${bindir}/tailscale
	install -Dm0644 ${S}/systemd/tailscaled.service ${D}${systemd_system_unitdir}/tailscaled.service
	install -Dm0644 ${S}/systemd/tailscaled.defaults ${D}${sysconfdir}/default/tailscaled
}

FILES:${PN} = "${sbindir}/tailscaled ${bindir}/tailscale ${systemd_system_unitdir}/tailscaled.service ${sysconfdir}/default/tailscaled"
