// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

// Host unit tests for the ADR-0016 control-socket AUTHORIZATION guards — the security-critical,
// kernel-free logic: a self-verb is honored only for a real agent-slice caller, and the broker
// TCB-register is honored ONLY for the exact broker cgroup (no prefix/substring/sibling/traversal
// can elevate an arbitrary cgroup). The map-write + live SO_PEERPIDFD attestation paths are
// exercised by the E0-armed qemu arm (scripts/qemu-e0-check.py).
package main

import "testing"

func TestIsAgentSelfCaller(t *testing.T) {
	good := []string{
		"/bulkhead.slice/bulkhead-agent.slice/bulkhead-agent@worker.service",
		"/bulkhead.slice/bulkhead-agent.slice/bulkhead-agent@d1-deadbeef-childprobe.service",
	}
	for _, p := range good {
		if !isAgentSelfCaller(p) {
			t.Fatalf("agent cgroup %q must be accepted as a self-caller", p)
		}
	}
	bad := []string{
		"/system.slice/bulkhead-collector.service",
		"/system.slice/bulkhead-broker.service",
		"/system.slice/foo.service",
		"/user.slice/user-0.slice/session-1.scope", // an operator root login
		"/", "",
		"/bulkhead.slice/bulkhead-agent.slice", // the slice itself, not an instance
	}
	for _, p := range bad {
		if isAgentSelfCaller(p) {
			t.Fatalf("non-agent cgroup %q must NOT be accepted as a self-caller", p)
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
