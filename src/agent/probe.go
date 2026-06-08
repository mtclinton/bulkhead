package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// runEgressProbe is the ADR-0034 increment-1 live check (dispatched from main). It runs
// inside the jailed agent's no-route netns and verifies, in order:
//
//  1. NOROUTE    — a direct dial to a public IP fails (the netns has no default route);
//  2. ISOLATED   — a direct dial to the host-loopback test service fails (the agent's own
//     loopback is separate from the host's, so the service is unreachable);
//  3. PROXY-OK   — the SAME host-loopback service IS reachable through the egress-proxy UDS
//     (the single mediated path works and bridges the namespace boundary);
//  4. PROXY-DENY — a non-allowlisted destination through the proxy is refused.
//
// It prints one "PROBE <name>: PASS|FAIL" line per check and returns 0 iff all pass.
func runEgressProbe() int {
	pub := envOr("BULKHEAD_PROBE_PUBLIC", "1.1.1.1:443")
	target := envOr("BULKHEAD_PROBE_TARGET", "127.0.0.1:8088")
	denied := envOr("BULKHEAD_PROBE_DENIED", "10.255.255.1:80")
	sock := os.Getenv("BULKHEAD_EGRESS_SOCK")

	ok := true
	report := func(name string, pass bool, detail string) {
		ok = ok && pass
		state := "FAIL"
		if pass {
			state = "PASS"
		}
		fmt.Printf("PROBE %s: %s — %s\n", name, state, detail)
	}

	// 1. NOROUTE — a direct connect to a public address must fail (no route in the netns).
	if c, err := net.DialTimeout("tcp", pub, 3*time.Second); err == nil {
		c.Close()
		report("NOROUTE", false, fmt.Sprintf("direct dial to %s SUCCEEDED (the netns has a route!)", pub))
	} else {
		report("NOROUTE", true, fmt.Sprintf("direct dial to %s failed as expected (%v)", pub, err))
	}

	// 2. ISOLATED — the host-loopback service is NOT on the agent's own loopback.
	if c, err := net.DialTimeout("tcp", target, 2*time.Second); err == nil {
		c.Close()
		report("ISOLATED", false, fmt.Sprintf("direct dial to %s SUCCEEDED (loopback is shared!)", target))
	} else {
		report("ISOLATED", true, fmt.Sprintf("direct dial to %s failed as expected (%v)", target, err))
	}

	if sock == "" {
		report("PROXY-OK", false, "BULKHEAD_EGRESS_SOCK unset — no proxy to test")
		return exitCode(ok)
	}

	// 3. PROXY-OK — the same target IS reachable through the mediated proxy path.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := proxyDial(ctx, sock, target)
	cancel()
	if err == nil {
		conn.Close()
		report("PROXY-OK", true, fmt.Sprintf("%s reachable via the egress proxy (mediated path works)", target))
	} else {
		report("PROXY-OK", false, fmt.Sprintf("%s NOT reachable via proxy (%v)", target, err))
	}

	// 4. PROXY-DENY — a non-allowlisted destination is refused by the proxy.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	c2, err2 := proxyDial(ctx2, sock, denied)
	cancel2()
	switch {
	case errors.Is(err2, errEgressDenied):
		report("PROXY-DENY", true, fmt.Sprintf("%s refused by the proxy allowlist as expected", denied))
	case err2 != nil:
		report("PROXY-DENY", false, fmt.Sprintf("%s refused but not via the allowlist (%v)", denied, err2))
	default:
		c2.Close()
		report("PROXY-DENY", false, fmt.Sprintf("%s was ALLOWED through the proxy (allowlist bypass!)", denied))
	}

	return exitCode(ok)
}

func exitCode(ok bool) int {
	if ok {
		return 0
	}
	return 1
}
