//go:build linux

// bulkhead-egress-proxy — the host-mediated egress boundary (ADR-0034, increment 1).
//
// The agent runs in a network namespace with NO default route; its only path to the
// outside is a connection to this proxy over a unix-domain socket bind-mounted into the
// jail. The proxy is the single, host-side, completely-mediatable egress point:
//
//   - it resolves DNS on the host (the guest has no resolver), closing the in-guest
//     DNS-tunnel exfiltration leg;
//   - it enforces the destination allowlist against a SINGLE canonical parse of the
//     request, so the policy check and the connect call can never disagree on the
//     destination — the parser-differential class (endsWith vs getaddrinfo on a
//     NUL-byte) that defeated allowlist proxies in the wild;
//   - then it splices bytes.
//
// TLS rides through opaque in this increment; TLS-termination + content inspection is
// increment 2. The BOUNDARY here is structural (the no-route netns), not the allowlist —
// the allowlist is the destination policy applied at an unbypassable placement.
package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// parseCIDRs parses a space/comma-separated CIDR list (the operator opt-in for internal
// egress destinations, e.g. a specific on-box router endpoint).
func parseCIDRs(s string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		_, n, err := net.ParseCIDR(f)
		if err != nil {
			return nil, fmt.Errorf("bad CIDR %q: %w", f, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func main() {
	log.SetFlags(0) // journald stamps the time

	// Pin the pure-Go resolver: it rejects ambiguous numeric IPv4 aliases (0x7f000001,
	// 2130706433, 127.1, ...) as NXDOMAIN instead of coercing them like libc getaddrinfo,
	// so the destination the allowlist approved is the destination resolved — no
	// policy-vs-resolver differential regardless of the image's nsswitch/cgo. (The build
	// recipe also sets CGO_ENABLED=0; this is the belt to that suspenders.)
	net.DefaultResolver.PreferGo = true

	sockPath := envOr("BULKHEAD_EGRESS_SOCK", "/run/bulkhead/egress.sock")
	allowPath := envOr("BULKHEAD_EGRESS_ALLOWLIST", "/etc/bulkhead/egress-allow.conf")

	allow, err := LoadAllowlist(allowPath)
	if err != nil {
		log.Fatalf("egress-proxy: allowlist %q: %v", allowPath, err)
	}
	log.Printf("egress-proxy: %s", allow.describe())

	// Operator opt-in for internal destinations; empty (default) denies every loopback /
	// private / link-local / metadata address at dial time.
	internalCIDRs, err := parseCIDRs(os.Getenv("BULKHEAD_EGRESS_ALLOW_INTERNAL_CIDRS"))
	if err != nil {
		log.Fatalf("egress-proxy: BULKHEAD_EGRESS_ALLOW_INTERNAL_CIDRS: %v", err)
	}
	if len(internalCIDRs) > 0 {
		log.Printf("egress-proxy: internal destinations permitted: %v", internalCIDRs)
	}

	if err := os.MkdirAll(filepath.Dir(sockPath), 0o755); err != nil {
		log.Fatalf("egress-proxy: mkdir %q: %v", filepath.Dir(sockPath), err)
	}
	// We own this path; replace a stale socket left by a previous run.
	if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("egress-proxy: stale socket %q: %v", sockPath, err)
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		log.Fatalf("egress-proxy: listen %q: %v", sockPath, err)
	}
	// 0660: the agent's DynamicUser reaches the socket via the shared bulkhead-egress
	// group. The no-route netns already makes this the only egress path, so the bytes
	// are mediated regardless of mode; the tight mode just keeps unrelated host users off.
	if err := os.Chmod(sockPath, 0o660); err != nil {
		log.Fatalf("egress-proxy: chmod %q: %v", sockPath, err)
	}

	p := NewProxy(allow, internalCIDRs)

	// Graceful shutdown: stop accepting; in-flight splices drain on their idle/total deadlines.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Printf("egress-proxy: shutting down")
		ln.Close()
	}()

	log.Printf("egress-proxy: listening on %s", sockPath)
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break // listener closed on signal
			}
			log.Printf("egress-proxy: accept: %v", err)
			continue
		}
		go p.handleConn(c)
	}
	os.Remove(sockPath)
}
