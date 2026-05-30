################################################################################
# SPDX-License-Identifier: AGPL-3.0-only
# bulkhead-router — OpenAI-compatible request router (local llama.cpp | Anthropic)
################################################################################

BULKHEAD_ROUTER_VERSION = 0.1.0
BULKHEAD_ROUTER_SITE = $(BR2_EXTERNAL_BULKHEAD_PATH)/../src/router
BULKHEAD_ROUTER_SITE_METHOD = local
BULKHEAD_ROUTER_LICENSE = AGPL-3.0-only

# Must match the module path in src/router/go.mod, or the golang-package infra
# infers a bogus import path from the local site directory.
BULKHEAD_ROUTER_GOMOD = github.com/mtclinton/bulkhead/router

# Pure stdlib (no external modules): builds offline as a single static binary.
# With BUILD_TARGETS=".", the binary is named after the package
# (bulkhead-router) and installed to /usr/bin by default.
BULKHEAD_ROUTER_LDFLAGS = -s -w -X main.BuildCommit=$(BULKHEAD_ROUTER_VERSION)

$(eval $(golang-package))
