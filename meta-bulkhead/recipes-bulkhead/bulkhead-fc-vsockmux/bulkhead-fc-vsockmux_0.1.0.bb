# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead Firecracker mediated-channel vsock<->unix splice (ADR-0042)"
HOMEPAGE = "https://github.com/mtclinton/bulkhead"
LICENSE = "AGPL-3.0-only"
LIC_FILES_CHKSUM = "file://LICENSE;md5=eb1e647870add0502f8f010b19de32af"

SRC_URI = "git://github.com/mtclinton/bulkhead.git;protocol=https;branch=main;destsuffix=git"
# ADR-0042: the transport-only mediation fabric bridging a microVM's vsock channel to the host
# egress-proxy/router UNIX sockets — serve-host = the per-instance HOST mux (Firecracker connects into its
# <uds>_<port> listeners, it splices to the fixed proxy/router UDS), serve-guest = the IN-VM forwarder
# (presents the agent's UNIX legs, splices to AF_VSOCK), probe/nonic = the slice-1 verifiers. Never derives
# a dial target from guest bytes; refuses a symlink/non-socket leg path; per-leg conn cap; deadline-driven
# half-close splice (adversarially reviewed + hardened, slices 1-4 live-proven). stdlib-only (raw AF_VSOCK
# syscalls — net.FileConn rejects vsock fds), so it builds with the native cross Go, no vendoring.
SRCREV = "8e9580b82e9302a94a988ff3a03171530d738a96"
S = "${WORKDIR}/git"

DEPENDS = "go-native"
inherit goarch
do_configure[noexec] = "1"

do_compile() {
	export GOOS=linux GOARCH="${TARGET_GOARCH}" CGO_ENABLED=0 GOTOOLCHAIN=local
	export GOPROXY=off GOFLAGS=-mod=mod
	export GOCACHE="${WORKDIR}/.gocache" GOPATH="${WORKDIR}/.gopath"
	cd ${S}/src/fc-vsockmux
	${STAGING_BINDIR_NATIVE}/go build -trimpath -o ${B}/bulkhead-fc-vsockmux .
}

do_install() {
	install -Dm0755 ${B}/bulkhead-fc-vsockmux ${D}${bindir}/bulkhead-fc-vsockmux
}

FILES:${PN} = "${bindir}/bulkhead-fc-vsockmux"
