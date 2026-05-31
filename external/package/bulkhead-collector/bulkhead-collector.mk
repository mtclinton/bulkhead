################################################################################
# SPDX-License-Identifier: AGPL-3.0-only
# bulkhead-collector — eBPF observe-only provenance collector + boot self-test
################################################################################

BULKHEAD_COLLECTOR_VERSION = 0.1.0
BULKHEAD_COLLECTOR_SITE = $(BR2_EXTERNAL_BULKHEAD_PATH)/../src/collector
BULKHEAD_COLLECTOR_SITE_METHOD = local
BULKHEAD_COLLECTOR_LICENSE = AGPL-3.0-only

# Must match the module path in src/collector/go.mod, or the golang-package
# infra infers a bogus import path from the local site directory.
BULKHEAD_COLLECTOR_GOMOD = github.com/mtclinton/bulkhead/collector

# cilium/ebpf is vendored under src/collector/vendor (committed): SITE_METHOD=local
# is never auto-vendored, and the build runs with -mod=vendor + GOPROXY=off.
# The BPF object is pre-generated (bpf2go) and embedded via go:embed, so the
# build needs only host-go — no clang/bpftool on the build host.
BULKHEAD_COLLECTOR_LDFLAGS = -s -w

$(eval $(golang-package))
