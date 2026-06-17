# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead provenance collector (BPF-LSM observer + hash-chained audit log)"
HOMEPAGE = "https://github.com/mtclinton/bulkhead"
LICENSE = "AGPL-3.0-only"
LIC_FILES_CHKSUM = "file://LICENSE;md5=eb1e647870add0502f8f010b19de32af"

SRC_URI = "git://github.com/mtclinton/bulkhead.git;protocol=https;branch=main;destsuffix=git"
# Pinned to 60774ac: completes the input-classification family started by b022155 (below), from the
# follow-up adversarial sweep of provenance.bpf.c. f729c44 — the UNSPECIFIED address (0.0.0.0, bare ::,
# ::ffff:0.0.0.0) classified DST_PUBLIC, but connect() lands on loopback inside ops->connect AFTER the LSM
# hook, so a public-but-not-loopback agent reached localhost services through the E2 gate; now
# classify_v4(0)/bare-:: => DST_LOOPBACK (+ a `probe connect4` AF_INET vehicle). bd7cfc5 — enforce_capset
# gain math now folds in the inheritable set (the inheritable+fcaps escalation was unflagged). 60774ac —
# classify_dest rejects a too-short sockaddr as DST_OTHER so a short connect can't classify on
# uninitialized bytes (the connect EINVALs either way — audit-chain determinism, not a bypass). All
# BPF-only, regenerated bpf_bpfel.o, strictly tightening; disasm-localized.
#
# Prior pin b022155: classify_dest() now classifies IPv4-mapped IPv6 (::ffff:0:0/96) by its embedded v4,
# closing the E2 egress-class bypass where ::ffff:169.254.169.254 / ::ffff:127.0.0.1 / v4-mapped RFC1918
# classified as DST_PUBLIC instead of LINKLOCAL/LOOPBACK/PRIVATE (regenerated bpf_bpfel.o). Also adds the
# `probe connect6` E2-class probe. Carries the attestation-audit snapshot (672fcea): posture gate
# count==expectedTCBCount (7fec4c7) + tpmMu robustness-debt note, ADR-0030 boot-gate hardening (3618d59
# torn-tail + 1e76ea0 empty-flag fail-closed), ADR-0029 transactional append (7b545ea) + race fixes
# (52f9ab9, dbda009), 015ef04/7c5bc17 audit hardening, ADR-0027 verify-audit router-chain case,
# cilium/ebpf v0.17.3, Go 1.22-buildable, ADR-0026 no-rewind.
# Bumped 60774ac -> 19505b6 for verify.go chainDomain: verify-audit now maps an audit-egress path to the
# "egress-proxy" domain so it can verify the egress proxy's signed chain (ADR-0034/0017). The BPF program
# (provenance.bpf.c / bpf_bpfel.o) is UNCHANGED from 60774ac — only the userspace verifier gained the case.
SRCREV = "d290d1e1ac01e0e77b42f90fcdfa8d5d2de64504"
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
