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
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
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

// upstreamRoots is the trust pool the proxy verifies the REAL upstream leg against (so the MITM
// never downgrades the agent's authentication). Defaults to the host Web-PKI roots; a test/dev
// build can add a self-signed upstream's cert via BULKHEAD_EGRESS_UPSTREAM_ROOTS (a PEM file) so the
// proxy validates a loopback upstream without internet — prod stays on the unaugmented system pool.
func upstreamRoots() *x509.CertPool {
	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if f := os.Getenv("BULKHEAD_EGRESS_UPSTREAM_ROOTS"); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			roots.AppendCertsFromPEM(b)
			log.Printf("egress-proxy: added upstream roots from %s", f)
		} else {
			log.Printf("egress-proxy: BULKHEAD_EGRESS_UPSTREAM_ROOTS %q: %v", f, err)
		}
	}
	return roots
}

func parsePorts(s string) map[string]bool {
	m := map[string]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		m[f] = true
	}
	return m
}

func envIntOr(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// methodSet parses a comma-list of HTTP methods into an UPPERCASE set (so a lowercase "post" cannot
// dodge a "POST" rule). Empty input => nil (no method restriction). inc2 sub-B.
func methodSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, m := range splitNonEmpty(s) {
		out[strings.ToUpper(m)] = true
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func main() {
	log.SetFlags(0) // journald stamps the time

	// `bulkhead-egress-proxy --provision-ca <dir>` (ADR-0034 inc2): a first-boot oneshot that mints
	// the on-device re-signing CA into <dir> (idempotent). Same binary so no extra dep/openssl.
	if len(os.Args) >= 3 && os.Args[1] == "--provision-ca" {
		if err := provisionCA(os.Args[2]); err != nil {
			log.Fatalf("egress-proxy: provision-ca %q: %v", os.Args[2], err)
		}
		log.Printf("egress-proxy: re-signing CA ready in %s", os.Args[2])
		return
	}

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

	// The signed egress-decision chain (ADR-0017/0034): every allow/deny is recorded, and the
	// allow path fails closed if it can't be. Opening it is mandatory — refuse to run an
	// unauditable egress boundary (a missing sealed seed under BULKHEAD_REQUIRE_SEALED_KEY=1
	// fails here, as it does for the collector/router).
	audit, err := openAuditLog("egress-proxy", "provenance.jsonl")
	if err != nil {
		log.Fatalf("egress-proxy: audit chain: %v", err)
	}
	defer audit.Close()

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
	// 0666 (inc1): the agent is a DynamicUser distinct from this proxy's DynamicUser, so a
	// group-gated 0660 needs a shared static group — deferred as a hardening follow-up. The
	// no-route netns already makes this the ONLY egress path and the proxy mediates every
	// byte regardless of who connects, so the mode is not the boundary here.
	if err := os.Chmod(sockPath, 0o666); err != nil {
		log.Fatalf("egress-proxy: chmod %q: %v", sockPath, err)
	}

	p := NewProxy(allow, internalCIDRs, audit)

	// inc2 (ADR-0034): load the re-signing CA. With BULKHEAD_REQUIRE_MITM_CA=1 a missing CA is fatal
	// here (fail-closed: an inspect-marked TLS flow is never spliced uninspected). Without a CA the
	// proxy runs as a pure inc1 boundary and inspect-marked flows take an explicit passthrough record.
	ca, err := loadMITMCA()
	if err != nil {
		log.Fatalf("egress-proxy: re-signing CA: %v", err)
	}
	if ca != nil {
		p.mitm = ca
		p.realRoots = upstreamRoots()
		p.tlsPorts = parsePorts(envOr("BULKHEAD_EGRESS_TLS_PORTS", "443"))
		p.maxReqBytes = int64(envIntOr("BULKHEAD_EGRESS_MAX_REQ_BYTES", 1<<20))
		p.denyNeedles = splitNonEmpty(os.Getenv("BULKHEAD_EGRESS_DENY_NEEDLES"))
		p.allowMethods = methodSet(os.Getenv("BULKHEAD_EGRESS_INSPECT_METHODS"))
		log.Printf("egress-proxy: TLS-termination enabled (inspect tls-ports=%v max-req=%d needles=%d methods=%v)",
			keys(p.tlsPorts), p.maxReqBytes, len(p.denyNeedles), keys(p.allowMethods))
	} else {
		log.Printf("egress-proxy: no re-signing CA — inc1 boundary only (inspect-marked flows pass through, recorded)")
	}

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
