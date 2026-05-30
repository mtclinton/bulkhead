// SPDX-License-Identifier: AGPL-3.0-only
package main

// Decision is the outcome of the routing rule.
type Decision struct {
	Route  Route
	Reason string
}

// promptLen approximates request size as the total characters of message
// content. It is a coarse, deterministic proxy that separates short interactive
// prompts from long ones. It is not tokenization, and intentionally so: the rule
// must be simple and predictable.
func promptLen(req *ChatRequest) int {
	n := 0
	for _, m := range req.Messages {
		n += len(m.Content)
	}
	return n
}

// decide applies the bulkhead routing rule. The client-supplied route is
// advisory and DOWNGRADE-ONLY: a client may force the free local tier, but may
// NOT force the paid Anthropic tier — otherwise an unauthenticated caller could
// drive cost (denial-of-wallet) by tagging every request route=api. The length
// threshold is the only path to the API.
func decide(req *ChatRequest, threshold int, def Route) Decision {
	if req.Route == RouteLocal {
		return Decision{RouteLocal, "client downgrade to local"}
	}
	// req.Route == RouteAPI is intentionally ignored: clients cannot force the
	// paid tier.
	if promptLen(req) >= threshold {
		return Decision{RouteAPI, "prompt length >= threshold"}
	}
	return Decision{def, "default (short prompt)"}
}
