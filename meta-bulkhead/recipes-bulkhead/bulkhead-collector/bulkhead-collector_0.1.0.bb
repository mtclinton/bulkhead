# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead provenance collector (BPF-LSM observer + hash-chained audit log)"
HOMEPAGE = "https://github.com/mtclinton/bulkhead"
LICENSE = "AGPL-3.0-only"
LIC_FILES_CHKSUM = "file://LICENSE;md5=eb1e647870add0502f8f010b19de32af"

SRC_URI = "git://github.com/mtclinton/bulkhead.git;protocol=https;branch=main;destsuffix=git"
# Pinned to b022155: classify_dest() now classifies IPv4-mapped IPv6 (::ffff:0:0/96) by its embedded v4,
# closing the E2 egress-class bypass where ::ffff:169.254.169.254 / ::ffff:127.0.0.1 / v4-mapped RFC1918
# classified as DST_PUBLIC instead of LINKLOCAL/LOOPBACK/PRIVATE (regenerated bpf_bpfel.o). Also adds the
# `probe connect6` E2-class probe. Carries the attestation-audit snapshot (672fcea): posture gate
# count==expectedTCBCount (7fec4c7) + tpmMu robustness-debt note, ADR-0030 boot-gate hardening (3618d59
# torn-tail + 1e76ea0 empty-flag fail-closed), ADR-0029 transactional append (7b545ea) + race fixes
# (52f9ab9, dbda009), 015ef04/7c5bc17 audit hardening, ADR-0027 verify-audit router-chain case,
# cilium/ebpf v0.17.3, Go 1.22-buildable, ADR-0026 no-rewind.
SRCREV = "b022155b52df3efb4cc08defbb4a0275c5123c83"
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
