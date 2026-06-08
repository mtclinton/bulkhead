//go:build linux

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, content string) string {
	t.Helper()
	p := filepath.Join(dir, "allow.conf")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// readRequest must reject any control byte before the newline — the NUL-byte case is the
// exact differential (host\x00.evil.com passing endsWith() while getaddrinfo truncates)
// that defeated a shipping allowlist proxy for ~130 releases (ADR-0034).
func TestReadRequestRejectsControlBytes(t *testing.T) {
	bad := []string{
		"CONNECT host\x00.evil.com:443", // embedded NUL
		"CONNECT host:443\rGET /",       // CR injection
		"CONNECT\tfoo:1",                // TAB
	}
	for _, tc := range bad {
		a, b := net.Pipe()
		go func() { io.WriteString(b, tc+"\n"); b.Close() }()
		_, _, err := readRequest(a)
		a.Close()
		if err == nil {
			t.Errorf("expected reject for %q", tc)
		}
	}
}

func TestReadRequestParse(t *testing.T) {
	ok := []struct{ in, host, port string }{
		{"CONNECT api.anthropic.com:443", "api.anthropic.com", "443"},
		{"CONNECT 127.0.0.1:8080", "127.0.0.1", "8080"},
		{"CONNECT [2606:4700::1111]:443", "2606:4700::1111", "443"},
	}
	for _, tc := range ok {
		a, b := net.Pipe()
		go func() { io.WriteString(b, tc.in+"\n"); b.Close() }()
		h, p, err := readRequest(a)
		a.Close()
		if err != nil || h != tc.host || p != tc.port {
			t.Errorf("%q -> (%q,%q,%v), want (%q,%q,nil)", tc.in, h, p, err, tc.host, tc.port)
		}
	}
	bad := []string{
		"GET / HTTP/1.1",           // not CONNECT
		"CONNECT noport",           // missing port
		"CONNECT host:0",           // port out of range
		"CONNECT host:99999",       // port out of range
		"CONNECT bad_host.com:443", // illegal underscore in label
		"CONNECT -lead.com:443",    // leading hyphen
	}
	for _, in := range bad {
		a, b := net.Pipe()
		go func() { io.WriteString(b, in+"\n"); b.Close() }()
		_, _, err := readRequest(a)
		a.Close()
		if err == nil {
			t.Errorf("expected reject for %q", in)
		}
	}
}

func TestReadRequestTooLong(t *testing.T) {
	a, b := net.Pipe()
	go func() { io.WriteString(b, "CONNECT "+strings.Repeat("a", 400)+":443\n"); b.Close() }()
	if _, _, err := readRequest(a); err == nil {
		t.Error("expected reject for overlong request")
	}
	a.Close()
}

func TestAllowlist(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "allow.conf")
	os.WriteFile(p, []byte("# comment\napi.anthropic.com\n.example.com\n10.0.0.0/8\n1.2.3.4\n"), 0o644)
	a, err := LoadAllowlist(p)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		want bool
	}{
		{"api.anthropic.com", true},
		{"API.ANTHROPIC.COM", true}, // case-insensitive
		{"evil.com", false},
		{"example.com", true},     // suffix matches the apex
		{"x.example.com", true},   // and subdomains
		{"notexample.com", false}, // not a subdomain of example.com
		{"10.1.2.3", true},        // CIDR
		{"11.1.2.3", false},
		{"1.2.3.4", true}, // exact IP
		{"1.2.3.5", false},
	}
	for _, c := range cases {
		if got := a.Allows(c.host); got != c.want {
			t.Errorf("Allows(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestAllowlistFailClosedAndStar(t *testing.T) {
	// missing file -> deny all
	missing, err := LoadAllowlist(filepath.Join(t.TempDir(), "nope.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if missing.Allows("anything.com") {
		t.Error("missing allowlist should be fail-closed")
	}
	// "*" -> allow all
	dir := t.TempDir()
	p := filepath.Join(dir, "all.conf")
	os.WriteFile(p, []byte("*\n"), 0o644)
	star, _ := LoadAllowlist(p)
	if !star.Allows("anything.com") {
		t.Error("'*' allowlist should permit all")
	}
}

// Numeric IPv4 aliases that net.ParseIP rejects but getaddrinfo would coerce to an address
// must be refused as hosts — otherwise they pass the name allowlist yet resolve elsewhere
// (the policy-vs-resolver differential the proxy exists to foreclose).
func TestValidateHostNumericAlias(t *testing.T) {
	reject := []string{"0x7f000001", "2130706433", "0177.0.0.1", "127.1", "127.0.0.01", "1", "012"}
	for _, h := range reject {
		if err := validateHost(h); err == nil {
			t.Errorf("validateHost(%q) accepted, want reject", h)
		}
	}
	accept := []string{"api.anthropic.com", "8.8.8.8", "127.0.0.1", "a1.example.com", "x-y.test"}
	for _, h := range accept {
		if err := validateHost(h); err != nil {
			t.Errorf("validateHost(%q) = %v, want accept", h, err)
		}
	}
}

// checkDialAddr is the SSRF guard: internal address classes are denied on the actual
// resolved address unless the operator opted that CIDR in.
func TestCheckDialAddr(t *testing.T) {
	_, loop, _ := net.ParseCIDR("127.0.0.0/8")
	deny := []string{
		"127.0.0.1:80",          // loopback
		"169.254.169.254:80",    // cloud metadata (link-local)
		"10.1.2.3:443",          // RFC-1918
		"192.168.0.5:443",       // RFC-1918
		"100.64.0.1:443",        // CGNAT
		"0.0.0.0:80",            // unspecified
		"[::1]:443",             // IPv6 loopback
		"[::ffff:127.0.0.1]:80", // v4-mapped loopback
	}
	for _, a := range deny {
		if err := checkDialAddr(a, nil); err == nil {
			t.Errorf("checkDialAddr(%q, deny-all) accepted, want deny", a)
		}
	}
	allow := []string{"8.8.8.8:443", "1.1.1.1:80", "[2606:4700::1111]:443"}
	for _, a := range allow {
		if err := checkDialAddr(a, nil); err != nil {
			t.Errorf("checkDialAddr(%q) = %v, want allow", a, err)
		}
	}
	// loopback becomes reachable once opted in
	if err := checkDialAddr("127.0.0.1:80", []*net.IPNet{loop}); err != nil {
		t.Errorf("checkDialAddr(loopback, opted-in) = %v, want allow", err)
	}
}

// A tunnel that goes silent after OK is reclaimed within the idle bound (not held forever).
func TestSpliceIdleReclaim(t *testing.T) {
	// upstream that accepts and then stays silent (never sends, never closes)
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			select {} // hold open, silent
		}
	}()
	_, port, _ := net.SplitHostPort(up.Addr().String())

	dir := t.TempDir()
	al, _ := LoadAllowlist(writeFile(t, dir, "127.0.0.1\n"))
	_, loop, _ := net.ParseCIDR("127.0.0.0/8")
	p := NewProxy(al, []*net.IPNet{loop}, nil)
	p.idleTimeout = 200 * time.Millisecond // shrink the idle bound for the test

	sock := filepath.Join(dir, "egress.sock")
	ln, _ := net.Listen("unix", sock)
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(c)
		}
	}()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT 127.0.0.1:%s\n", port)
	br := bufio.NewReader(c)
	if reply, _ := br.ReadString('\n'); strings.TrimSpace(reply) != "OK" {
		t.Fatalf("want OK, got %q", reply)
	}
	// Now go silent; the proxy must reclaim (close) the tunnel within ~idleTimeout.
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("expected EOF/timeout after idle reclaim, got a byte")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("tunnel was NOT reclaimed within 2s (idle deadline not enforced)")
	}
}

// handleConn records both an allow and a deny into the signed chain (record-before-act on allow).
func TestHandleConnRecordsToChain(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	_, port, _ := net.SplitHostPort(echo.Addr().String())

	dir := t.TempDir()
	al, _ := LoadAllowlist(writeFile(t, dir, "127.0.0.1\n"))
	_, loop, _ := net.ParseCIDR("127.0.0.0/8")
	audit := newTestAuditLog(t, filepath.Join(dir, "provenance.jsonl"))
	p := NewProxy(al, []*net.IPNet{loop}, audit)

	sock := filepath.Join(dir, "egress.sock")
	ln, _ := net.Listen("unix", sock)
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go p.handleConn(c)
		}
	}()

	c, _ := net.Dial("unix", sock) // ALLOW
	fmt.Fprintf(c, "CONNECT 127.0.0.1:%s\n", port)
	if reply, _ := bufio.NewReader(c).ReadString('\n'); strings.TrimSpace(reply) != "OK" {
		t.Fatalf("allow: want OK, got %q", reply)
	}
	c.Close()

	c2, _ := net.Dial("unix", sock) // DENY (8.8.8.8 not in the 127.0.0.1-only allowlist)
	fmt.Fprintf(c2, "CONNECT 8.8.8.8:80\n")
	if r2, _ := bufio.NewReader(c2).ReadString('\n'); !strings.HasPrefix(r2, "ERR denied") {
		t.Fatalf("deny: want ERR denied, got %q", r2)
	}
	c2.Close()
	audit.Close()

	data, _ := os.ReadFile(filepath.Join(dir, "provenance.jsonl"))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 chain records, got %d: %s", len(lines), data)
	}
	var allow, deny auditRecord
	json.Unmarshal([]byte(lines[0]), &allow)
	json.Unmarshal([]byte(lines[1]), &deny)
	if allow.Decision != "allow" || !strings.Contains(allow.Mode, fmt.Sprintf("dst=127.0.0.1:%s", port)) {
		t.Fatalf("allow record wrong: %+v", allow)
	}
	if deny.Decision != "deny" || !strings.Contains(deny.Mode, "dst=8.8.8.8:80") || !strings.Contains(deny.Mode, "allowlist") {
		t.Fatalf("deny record wrong: %+v", deny)
	}
}

// End-to-end: an allowed CONNECT reaches a host-side echo server through the proxy; a
// non-allowlisted destination is refused before any dial.
func TestProxyEndToEnd(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	_, port, _ := net.SplitHostPort(echo.Addr().String())

	dir := t.TempDir()
	alPath := filepath.Join(dir, "allow.conf")
	os.WriteFile(alPath, []byte("127.0.0.1\n"), 0o644)
	al, err := LoadAllowlist(alPath)
	if err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(dir, "egress.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// The echo upstream is on loopback, which the IP-class deny blocks by default; opt it
	// in explicitly (as an operator would for an internal endpoint) so this exercises the
	// allow path rather than the SSRF guard.
	_, loop, _ := net.ParseCIDR("127.0.0.0/8")
	p := NewProxy(al, []*net.IPNet{loop}, nil)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(c)
		}
	}()

	// ALLOW: connect, request, OK, echo round-trip.
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT 127.0.0.1:%s\n", port)
	br := bufio.NewReader(c)
	reply, _ := br.ReadString('\n')
	if strings.TrimSpace(reply) != "OK" {
		t.Fatalf("ALLOW: want OK, got %q", reply)
	}
	io.WriteString(c, "ping")
	got := make([]byte, 4)
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "ping" {
		t.Fatalf("ALLOW: echo round-trip failed: %q %v", got, err)
	}

	// DENY: a host not in the allowlist is refused (no dial).
	c2, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	fmt.Fprintf(c2, "CONNECT 10.9.9.9:80\n")
	reply2, _ := bufio.NewReader(c2).ReadString('\n')
	if !strings.HasPrefix(reply2, "ERR denied") {
		t.Fatalf("DENY: want 'ERR denied', got %q", reply2)
	}
}
