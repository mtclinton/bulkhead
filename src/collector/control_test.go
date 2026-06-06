// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

// Host unit tests for the ADR-0016 control-socket AUTHORIZATION guards — the security-critical,
// kernel-free logic: a self-verb is honored only for a real agent-slice caller, and the broker
// TCB-register is honored ONLY for the exact broker cgroup (no prefix/substring/sibling/traversal
// can elevate an arbitrary cgroup). The map-write + live SO_PEERPIDFD attestation paths are
// exercised by the E0-armed qemu arm (scripts/qemu-e0-check.py).
package main

import "testing"

func TestIsAgentCgroup(t *testing.T) {
	good := []string{
		"/bulkhead.slice/bulkhead-agent.slice/bulkhead-agent@worker.service",
		"/bulkhead.slice/bulkhead-agent.slice/bulkhead-agent@d1-deadbeef-childprobe.service",
		"/bulkhead-agent.slice/bulkhead-agent@worker.service", // un-nested form (defensive)
	}
	for _, p := range good {
		if !isAgentCgroup(p) {
			t.Fatalf("agent jail cgroup %q must be accepted", p)
		}
	}
	bad := []string{
		"/system.slice/bulkhead-collector.service",
		"/system.slice/bulkhead-broker.service",
		"/system.slice/foo.service",
		"/user.slice/user-0.slice/session-1.scope", // an operator root login
		"/", "",
		"/bulkhead.slice/bulkhead-agent.slice", // the slice itself, not an instance
		// ADR-0016-review C1: anchored match rejects crafted uid-0 paths that merely EMBED the
		// marker (strings.Contains used to admit all of these — bounded, but a precision gap):
		"/bulkhead.slice/bulkhead-agent.slice/bulkhead-agent@worker.service/payload.scope", // nested sub-cgroup leaf
		"/user.slice/bulkhead-agent.slice/bulkhead-agent@x.service",                        // marker slice under the wrong parent
		"/system.slice/bulkhead-agent.slice/bulkhead-agent@evil.service",                   // systemd-run --slice=bulkhead-agent.slice helper
		"/bulkhead.slice/bulkhead-agent.slice/bulkhead-agent@worker.service.evil",          // suffix past .service
		"bulkhead-agent.slice/bulkhead-agent@x.service",                                    // missing leading slash
	}
	for _, p := range bad {
		if isAgentCgroup(p) {
			t.Fatalf("non-agent / crafted cgroup %q must NOT be accepted", p)
		}
	}
}

func TestIsBrokerCaller(t *testing.T) {
	// brokerCgroupPath = /sys/fs/cgroup/system.slice/bulkhead-broker.service => rel below.
	if !isBrokerCaller("/system.slice/bulkhead-broker.service") {
		t.Fatal("the exact broker cgroup must be accepted")
	}
	// Clean-equivalent forms still match (trailing slash, redundant dots).
	for _, p := range []string{
		"/system.slice/bulkhead-broker.service/",
		"/system.slice/./bulkhead-broker.service",
	} {
		if !isBrokerCaller(p) {
			t.Fatalf("clean-equivalent broker path %q must be accepted", p)
		}
	}
	// NONE of these may pass — a nested/sibling/substring/traversal cgroup must never drive a
	// TCB registration (the anti-arbitrary-register guard).
	bad := []string{
		"/system.slice/bulkhead-broker.service/sub.scope",      // nested child
		"/system.slice/bulkhead-broker.service.d",              // substring-prefix sibling
		"/system.slice/bulkhead-broker-evil.service",           // sibling
		"/system.slice/bulkhead-collector.service",             // the collector
		"/bulkhead.slice/bulkhead-agent.slice/bulkhead-agent@x.service", // an agent
		"/system.slice/bulkhead-broker.service/../evil.service", // traversal
		"/", "", "system.slice/bulkhead-broker.service", // missing leading slash
	}
	for _, p := range bad {
		if isBrokerCaller(p) {
			t.Fatalf("non-broker cgroup %q must NOT be accepted for TCB registration", p)
		}
	}
}

// TestShouldRetryControl — regression for the ADR-0018 boot-race retry gap. egress-set-self (and the
// other one-shot verbs) used to fail on the FIRST non-OK reply, so a cold-boot dial that lost the race
// against the collector binding the socket (controlRPC returns a "control dial ..." TRANSPORT error)
// failed the agent unit outright. The fix retries TRANSPORT failures for every verb while keeping a
// SERVER rejection ("ERR ...") terminal, so a genuine rejection still fail-closes fast. wait-broker-tcb
// remains the sole verb that polls on a server reply too (its "ERR not-registered" is the poll loop).
func TestShouldRetryControl(t *testing.T) {
	// Transport failures (the boot race) are retried for EVERY verb — controlRPC wraps dial/send/read
	// errors with a "control " prefix.
	transport := []string{"control dial: no such file or directory", "control send: broken pipe", "control read: EOF"}
	for _, verb := range []string{"egress-set-self", "egress-clear-self", "grant-clear-self", "tcb-register-broker", "wait-broker-tcb"} {
		for _, resp := range transport {
			if !shouldRetryControl(verb, resp) {
				t.Fatalf("verb %q must RETRY a transport failure %q (the boot race)", verb, resp)
			}
		}
	}
	// A SERVER rejection is terminal for the one-shot verbs — fail-closed fast, do NOT hang the 30s
	// boot-race window on a genuine rejection.
	for _, verb := range []string{"egress-set-self", "egress-clear-self", "grant-clear-self", "tcb-register-broker"} {
		for _, resp := range []string{"ERR not-an-agent", "ERR bad-classes", "ERR map", "ERR update", "ERR not-broker"} {
			if shouldRetryControl(verb, resp) {
				t.Fatalf("verb %q must NOT retry a server rejection %q (must fail-closed fast)", verb, resp)
			}
		}
	}
	// wait-broker-tcb is the exception: it polls on a server reply too, since "ERR not-registered" is
	// its expected loop condition while the broker self-registers into tcb_cgroups.
	for _, resp := range []string{"ERR not-registered", "ERR map", "ERR broker-cgroup"} {
		if !shouldRetryControl("wait-broker-tcb", resp) {
			t.Fatalf("wait-broker-tcb must keep polling on server reply %q", resp)
		}
	}
}
