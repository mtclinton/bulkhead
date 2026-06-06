# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead provenance collector (BPF-LSM observer + hash-chained audit log)"
HOMEPAGE = "https://github.com/mtclinton/bulkhead"
LICENSE = "AGPL-3.0-only"
LIC_FILES_CHKSUM = "file://LICENSE;md5=eb1e647870add0502f8f010b19de32af"

SRC_URI = "git://github.com/mtclinton/bulkhead.git;protocol=https;branch=main;destsuffix=git"
# Pinned to the ADR-0029 snapshot: the two collector authority-surface race fixes —
# 52f9ab9 (control-socket boot-race retry classification, shouldRetryControl) and dbda009
# (BH-001 gc grant_once witnessed-live guard) — plus the 015ef04/7c5bc17 security-audit
# hardening that landed since the e3239ef pin. (Still carries the ADR-0027 verify-audit
# router-chain case, the cilium/ebpf v0.17.3 re-pin, Go 1.22-buildable, ADR-0026 no-rewind.)
SRCREV = "9aa207d69d3d3815600da99a377edb20f7c75677"
S = "${WORKDIR}/git"

DEPENDS = "go-native"
inherit goarch

# No configure step: we build directly with go in do_compile. ${S} is the repo root,
# whose Makefile is the Buildroot prototype's (clean pulls in a buildroot target that
# errors); keep base_do_configure from running `make clean` against it.
do_configure[noexec] = "1"

# Pure-Go (cilium/ebpf, CGO off). The bpf2go object (bpf_bpfel.o) is committed, so
# no clang/bpf2go at build time; modules are vendored, so no network. Same
# repo-subdir approach as bulkhead-router.
do_compile() {
	export GOOS=linux GOARCH="${TARGET_GOARCH}" CGO_ENABLED=0 GOTOOLCHAIN=local
	export GOFLAGS=-mod=vendor GOPROXY=off
	export GOCACHE="${WORKDIR}/.gocache" GOPATH="${WORKDIR}/.gopath"
	cd ${S}/src/collector
	${STAGING_BINDIR_NATIVE}/go build -trimpath -o ${B}/bulkhead-collector .
}

do_install() {
	install -Dm0755 ${B}/bulkhead-collector ${D}${bindir}/bulkhead-collector
}

FILES:${PN} = "${bindir}/bulkhead-collector"
