// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"regexp"
	"strings"
)

// Directive is a parsed model instruction. Kind is "tool" or "final".
type Directive struct {
	Kind string // "tool" | "final"
	Name string // tool name (Kind=="tool")
	Arg  string
}

const maxArgLen = 2048

// directiveRe matches a line that STARTS with TOOL or FINAL (word-boundary), tolerating
// trailing content. We deliberately use a constrained single-line text protocol rather than
// OpenAI function-calling: a small q4 local model emits tool_calls JSON unreliably, and the
// router proxies llama-server bodies verbatim (no server-side tool/grammar layer).
var directiveRe = regexp.MustCompile(`^(TOOL|FINAL)\b[ \t]*(.*)$`)

// parse scans the model reply for the FIRST line that is a TOOL or FINAL directive — tolerant
// IN (small models pad with prose), strict OUT (the caller validates the tool name + arg).
// Security never depends on the model behaving: no match returns ok=false and the loop feeds a
// corrective observation that costs one bounded step.
func parse(reply string) (Directive, bool) {
	for _, line := range strings.Split(reply, "\n") {
		m := directiveRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		rest := strings.TrimSpace(m[2])
		if len(rest) > maxArgLen {
			rest = rest[:maxArgLen]
		}
		if strings.EqualFold(m[1], "FINAL") {
			return Directive{Kind: "final", Arg: rest}, true
		}
		name, arg, _ := strings.Cut(rest, " ")
		return Directive{Kind: "tool", Name: strings.ToLower(strings.TrimSpace(name)), Arg: strings.TrimSpace(arg)}, true
	}
	return Directive{}, false
}
