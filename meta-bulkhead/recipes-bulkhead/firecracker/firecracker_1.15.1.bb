# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "Firecracker microVM monitor + jailer (ADR-0031 hostile tier / ADR-0042 mediated channel)"
HOMEPAGE = "https://firecracker-microvm.github.io"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/Apache-2.0;md5=89aea4e17d99a7cacdbeed46a0096b10"

# Prebuilt static x86_64 release (v1.15.1 — the exact artifact the ADR-0031 feasibility spike and the
# ADR-0042 mediated-channel slices 1-4 validated host-side: a microVM boots bulkhead's guest kernel under
# KVM, the unchanged agent reaches the host egress proxy ONLY over the vsock leg, the real allowlist +
# signed chain hold over vsock, and firecracker holds no host network socket). firecracker is the VMM; the
# jailer is the per-instance confinement (uid/chroot/empty-netns/cgroup) the hostile-tier launcher runs it
# under (ADR-0042 slice 6). Single self-contained static Go-free Rust binaries — no build, just install +
# verify the sum.
SRC_URI = "https://github.com/firecracker-microvm/firecracker/releases/download/v${PV}/firecracker-v${PV}-x86_64.tgz;sha256sum=d4a32ab2322d887ca1bc4a4e7afa9cc35393e6362dfc2b3becb389d362e4275a"
S = "${WORKDIR}/release-v${PV}-x86_64"

COMPATIBLE_MACHINE = "qemux86-64"
# Prebuilt vendor binaries: skip the source/arch/strip QA that assumes we compiled them ourselves.
INSANE_SKIP:${PN} += "already-stripped ldflags"

do_install() {
	install -Dm0755 ${S}/firecracker-v${PV}-x86_64 ${D}${bindir}/firecracker
	install -Dm0755 ${S}/jailer-v${PV}-x86_64 ${D}${bindir}/jailer
}

FILES:${PN} = "${bindir}/firecracker ${bindir}/jailer"
