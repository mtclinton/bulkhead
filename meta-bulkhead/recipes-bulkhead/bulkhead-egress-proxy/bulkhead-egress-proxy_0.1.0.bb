# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead host-mediated egress proxy (ADR-0034 structural egress)"
HOMEPAGE = "https://github.com/mtclinton/bulkhead"
LICENSE = "AGPL-3.0-only"
LIC_FILES_CHKSUM = "file://LICENSE;md5=eb1e647870add0502f8f010b19de32af"

SRC_URI = "git://github.com/mtclinton/bulkhead.git;protocol=https;branch=main;destsuffix=git"
# Pinned to 42ac280: ADR-0034 inc1, the structural egress boundary. src/proxy (stdlib-only):
# single-canonical-parse CONNECT over a UDS, host-side DNS, advisory allowlist, post-resolution
# internal-IP deny (SSRF/metadata), bounded splice. Adversarially reviewed + hardened (4 findings).
SRCREV = "42ac2803bebba8e74cbaa1c328c614957c704e6a"
S = "${WORKDIR}/git"

DEPENDS = "go-native"
inherit goarch

# No configure step; ${S} is the repo root whose Makefile is the Buildroot prototype's.
do_configure[noexec] = "1"

# Pure-stdlib Go module in a repo subdir (src/proxy), built directly with the native cross
# Go. CGO_ENABLED=0 -> no cross toolchain AND the pure-Go resolver (which rejects the
# numeric-alias coercion the proxy guards against), matching net.DefaultResolver.PreferGo.
do_compile() {
	export GOOS=linux GOARCH="${TARGET_GOARCH}" CGO_ENABLED=0 GOTOOLCHAIN=local
	export GOPROXY=off GOFLAGS=-mod=mod
	export GOCACHE="${WORKDIR}/.gocache" GOPATH="${WORKDIR}/.gopath"
	cd ${S}/src/proxy
	${STAGING_BINDIR_NATIVE}/go build -trimpath -o ${B}/bulkhead-egress-proxy .
}

do_install() {
	install -Dm0755 ${B}/bulkhead-egress-proxy ${D}${bindir}/bulkhead-egress-proxy
}

FILES:${PN} = "${bindir}/bulkhead-egress-proxy"
