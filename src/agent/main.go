// SPDX-License-Identifier: AGPL-3.0-only
//
// bulkhead-agentd — the minimal-but-real bulkhead agent runtime (ADR-0014). It runs as the
// jailed payload (ExecStart of bulkhead-agent@.service): a bounded perceive->decide->act loop
// that does inference via the bulkhead router and acts through a small tool set. It is OUTSIDE
// the TCB — non-root DynamicUser, empty caps, @system-service seccomp — so it cannot bpf(),
// cannot touch a pinned map, and cannot reach the uid-0 approve.sock; the only path to more
// authority than its launch manifest is ASKING the TCB broker (which blocks for a human).
package main

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"
)

// BuildCommit is injected via -ldflags "-X main.BuildCommit=<sha>" (AGPL §13 source anchor).
var BuildCommit = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	// `bulkhead-agentd mockchat` is a TEST/DEMO-only canned OpenAI endpoint (its unit is never
	// [Install]-enabled). It is the SAME binary so the agent's HTTP path is byte-identical in
	// prod and qemu — only BULKHEAD_ROUTER_URL differs.
	if len(os.Args) >= 2 && os.Args[1] == "mockchat" {
		runMockChat()
		return
	}

	inst := "?"
	if len(os.Args) >= 2 {
		inst = os.Args[1]
	}
	task := os.Getenv("BULKHEAD_AGENT_TASK")
	if task == "" {
		log.Fatalf("agent[%s]: BULKHEAD_AGENT_TASK is empty — nothing to do", inst)
	}
	routerURL := envOr("BULKHEAD_ROUTER_URL", "http://127.0.0.1:8080")
	maxSteps := envInt("BULKHEAD_AGENT_MAX_STEPS", 6)
	deadline := time.Duration(envInt("BULKHEAD_AGENT_DEADLINE", 90)) * time.Second

	log.Printf("agent[%s]: build=%s router=%s max_steps=%d deadline=%s task=%q",
		inst, BuildCommit, routerURL, maxSteps, deadline, truncate(task, 120))

	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	ans, err := runLoop(ctx, routerURL, task, maxSteps, toolRegistry())
	if err != nil {
		log.Printf("agent[%s]: ABORTED: %v", inst, err)
		os.Exit(1)
	}
	log.Printf("agent[%s]: DONE: %s", inst, truncate(ans, 400))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
