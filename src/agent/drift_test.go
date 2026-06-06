// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"strings"
	"testing"
)

// TestToolRegistryAdvertised — drift guard (security-audit completeness lead). The agent's dispatch will
// invoke ANY tool name in toolRegistry() that the model emits; with all capabilities enabled, every such
// tool MUST be advertised in systemPrompt(). This fails the moment a future tool is added to the registry
// (model-callable) without documenting it in the prompt — an undocumented-capability footgun. (Conditionally
// gated tools also self-guard in Run(), but advertisement coherence is the explicit, cheap invariant.)
func TestToolRegistryAdvertised(t *testing.T) {
	t.Setenv("BULKHEAD_AGENT_NO_EXPAND", "")       // canExpand => systemPrompt advertises request_egress
	t.Setenv("BULKHEAD_AGENT_ALLOW_DELEGATE", "1") // => systemPrompt advertises delegate
	prompt := systemPrompt()
	for name := range toolRegistry() {
		if !strings.Contains(prompt, name) {
			t.Fatalf("tool %q is model-callable (in toolRegistry) but not advertised in systemPrompt() — drift", name)
		}
	}
}
