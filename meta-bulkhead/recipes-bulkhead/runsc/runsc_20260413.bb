# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "gVisor runsc — application-kernel / OCI runtime (ADR-0031 isolation substrate)"
HOMEPAGE = "https://gvisor.dev"
LICENSE = "Apache-2.0"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/Apache-2.0;md5=89aea4e17d99a7cacdbeed46a0096b10"

# Prebuilt static amd64 binary from the gVisor release channel (release-20260413 — the same artifact
# the ADR-0031 feasibility spike validated: rootless Systrap, host-surface collapse to gVisor's
# reimplemented kernel). A single self-contained Go binary — no build, just install + verify the sum.
SRC_URI = "https://storage.googleapis.com/gvisor/releases/release/20260413/x86_64/runsc;sha256sum=c97966a7bce00a6ce6de2f931b2b4cf0cbe979d5f47d9feda75f5bbbce0d93ad;downloadfilename=runsc"
S = "${WORKDIR}"

COMPATIBLE_MACHINE = "qemux86-64"
# Prebuilt vendor binary: skip the source/arch/strip QA that assumes we compiled it ourselves.
INSANE_SKIP:${PN} += "already-stripped ldflags"

do_install() {
	install -Dm0755 ${WORKDIR}/runsc ${D}${bindir}/runsc
}

FILES:${PN} = "${bindir}/runsc"
