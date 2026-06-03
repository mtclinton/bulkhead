# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead OpenAI-compatible request router"
HOMEPAGE = "https://github.com/mtclinton/bulkhead"
LICENSE = "AGPL-3.0-only"
LIC_FILES_CHKSUM = "file://LICENSE;md5=eb1e647870add0502f8f010b19de32af"

SRC_URI = "git://github.com/mtclinton/bulkhead.git;protocol=https;branch=main;destsuffix=git"
SRCREV = "b5711b086ce6c190cd4bf8e2eb1dc9815c7f5c12"
S = "${WORKDIR}/git"

DEPENDS = "go-native"
inherit goarch

# No configure step: we build directly with go in do_compile. ${S} is the repo root,
# whose Makefile is the Buildroot prototype's (clean pulls in a buildroot target that
# errors); keep base_do_configure from running `make clean` against it.
do_configure[noexec] = "1"

# The module lives in a repo subdir (src/router) and is pure stdlib, so build it
# directly with the native Go cross-compiler rather than via go.bbclass (which
# assumes module-at-repo-root). CGO_ENABLED=0 -> no cross toolchain needed.
do_compile() {
	export GOOS=linux GOARCH="${TARGET_GOARCH}" CGO_ENABLED=0 GOTOOLCHAIN=local
	export GOPROXY=off GOFLAGS=-mod=mod
	export GOCACHE="${WORKDIR}/.gocache" GOPATH="${WORKDIR}/.gopath"
	cd ${S}/src/router
	# Don't strip here (-s -w): let Yocto strip and split debug symbols.
	${STAGING_BINDIR_NATIVE}/go build -trimpath -o ${B}/bulkhead-router .
}

do_install() {
	install -Dm0755 ${B}/bulkhead-router ${D}${bindir}/bulkhead-router
}

FILES:${PN} = "${bindir}/bulkhead-router"
