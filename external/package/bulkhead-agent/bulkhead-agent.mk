################################################################################
# SPDX-License-Identifier: AGPL-3.0-only
# bulkhead-agent — the minimal-but-real jailed agent runtime (bulkhead-agentd)
################################################################################

BULKHEAD_AGENT_VERSION = 0.1.0
BULKHEAD_AGENT_SITE = $(BR2_EXTERNAL_BULKHEAD_PATH)/../src/agent
BULKHEAD_AGENT_SITE_METHOD = local
BULKHEAD_AGENT_LICENSE = AGPL-3.0-only

# Must match the module path in src/agent/go.mod.
BULKHEAD_AGENT_GOMOD = github.com/mtclinton/bulkhead/agent

# Pure stdlib (no external modules): builds offline as a single static binary named
# bulkhead-agentd (BUILD_TARGETS=".").
BULKHEAD_AGENT_LDFLAGS = -s -w -X main.BuildCommit=$(BULKHEAD_AGENT_VERSION)

$(eval $(golang-package))
