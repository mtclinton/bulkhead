//go:build linux

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
		"GET / HTTP/1.1",            // not CONNECT
		"CONNECT noport",            // missing port
		"CONNECT host:0",            // port out of range
		"CONNECT host:99999",        // port out of range
		"CONNECT bad_host.com:443",  // illegal underscore in label
		"CONNECT -lead.com:443",     // leading hyphen
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
	p := NewProxy(al)
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
