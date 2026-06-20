# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead minimal agent runtime (jailed tool-using loop)"
HOMEPAGE = "https://github.com/mtclinton/bulkhead"
LICENSE = "AGPL-3.0-only"
LIC_FILES_CHKSUM = "file://LICENSE;md5=eb1e647870add0502f8f010b19de32af"

SRC_URI = "git://github.com/mtclinton/bulkhead.git;protocol=https;branch=main;destsuffix=git"
# Pinned to 9f6226d ([81]): probe-egress gained a CRED self-test (the non-root in-sandbox agent reads
# its task credential) and a probe-memhog resource-limit vehicle (allocates+touches memory so the
# per-instance cgroup MemoryMax OOM-kills it), on top of the ADR-0034 inc1 mediated egress client.
SRCREV = "9f6226d4626ddcb09688c9676e99ea3631c3950a"
S = "${WORKDIR}/git"

DEPENDS = "go-native"
inherit goarch

# Same pattern as bulkhead-router: a pure-stdlib Go module in a repo subdir (src/agent),
# built directly with the native cross Go (CGO off -> no cross toolchain), not via go.bbclass.
do_configure[noexec] = "1"

do_compile() {
	export GOOS=linux GOARCH="${TARGET_GOARCH}" CGO_ENABLED=0 GOTOOLCHAIN=local
	export GOPROXY=off GOFLAGS=-mod=mod
	export GOCACHE="${WORKDIR}/.gocache" GOPATH="${WORKDIR}/.gopath"
	cd ${S}/src/agent
	${STAGING_BINDIR_NATIVE}/go build -trimpath -o ${B}/bulkhead-agent .
}

do_install() {
	install -Dm0755 ${B}/bulkhead-agent ${D}${bindir}/bulkhead-agent
}

FILES:${PN} = "${bindir}/bulkhead-agent"
