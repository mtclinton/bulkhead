//go:build linux

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLeafCacheBounded (ADR-0034 inc2 sub-B): the per-host leaf cache must stay bounded — otherwise an
// agent fetching unbounded distinct inspected hostnames (especially under the default-inspect knob) is
// a slow memory leak. Minting well past the cap keeps the cache at the bound, and every leaf — including
// a re-mint of an evicted host — stays valid (eviction trades memory for at most a cheap re-sign).
func TestLeafCacheBounded(t *testing.T) {
	m := testMITM(t)
	old := maxLeafCache
	maxLeafCache = 8
	defer func() { maxLeafCache = old }()

	for i := 0; i < maxLeafCache*3; i++ {
		leaf, err := m.leafFor(fmt.Sprintf("host%d.example.com", i))
		if err != nil {
			t.Fatalf("leafFor(host%d): %v", i, err)
		}
		if leaf == nil || len(leaf.Certificate) == 0 {
			t.Fatalf("host%d: empty leaf", i)
		}
		if len(m.cache) > maxLeafCache {
			t.Fatalf("after %d mints the cache holds %d leaves, want <= %d", i+1, len(m.cache), maxLeafCache)
		}
	}
	// a re-fetch of a (possibly evicted) host still returns a usable leaf — eviction never breaks correctness.
	if leaf, err := m.leafFor("host0.example.com"); err != nil || leaf == nil {
		t.Fatalf("re-mint after eviction failed: %v (leaf=%v)", err, leaf)
	}
}

// testMITM provisions a real on-device CA into a temp dir and builds a mitmCA from it (mirroring
// loadMITMCA's construction), so the tests exercise the actual provision + parse path.
func testMITM(t *testing.T) *mitmCA {
	t.Helper()
	dir := t.TempDir()
	if err := provisionCA(dir); err != nil {
		t.Fatal(err)
	}
	crtPEM, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	keyPEM, _ := os.ReadFile(filepath.Join(dir, "ca.key"))
	cert, key, err := parseCA(crtPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &mitmCA{cert: cert, key: key, leafKey: priv, leafPub: pub, cache: map[string]*tls.Certificate{}}
}

func TestAllowlistMode(t *testing.T) {
	content := "api.anthropic.com inspect\n.example.com passthrough\npin.host.com pinned\n10.0.0.0/8 inspect\nplainhost.com\n"
	al, err := LoadAllowlist(writeFile(t, t.TempDir(), content))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host    string
		mode    string
		allowed bool
	}{
		{"api.anthropic.com", modeInspect, true},
		{"x.example.com", modePassthrough, true},
		{"example.com", modePassthrough, true},
		{"pin.host.com", modePinned, true},
		{"10.1.2.3", modeInspect, true},
		{"plainhost.com", modePassthrough, true}, // no token -> default passthrough
		{"evil.com", modePassthrough, false},     // not allowed; Mode falls back to passthrough
	}
	for _, c := range cases {
		if got := al.Allows(c.host); got != c.allowed {
			t.Errorf("Allows(%q)=%v want %v", c.host, got, c.allowed)
		}
		if got := al.Mode(c.host); got != c.mode {
			t.Errorf("Mode(%q)=%q want %q", c.host, got, c.mode)
		}
	}
	// a bad mode token is a hard parse error (fail loud, not silently mis-handled)
	if _, err := LoadAllowlist(writeFile(t, t.TempDir(), "h.com bogus\n")); err == nil {
		t.Error("bad mode token should error")
	}
	// a specific inspect entry wins over a "* passthrough" default
	al2, _ := LoadAllowlist(writeFile(t, t.TempDir(), "* passthrough\nspecial.com inspect\n"))
	if al2.Mode("special.com") != modeInspect {
		t.Error("specific entry should win over *")
	}
	if al2.Mode("other.com") != modePassthrough {
		t.Error("* default mode should be passthrough")
	}
}

// TestDefaultEgressModeKnob (ADR-0034 inc2 sub-B): BULKHEAD_EGRESS_DEFAULT_MODE flips the disposition
// of UNMARKED allowlist entries — the high-assurance "inspect everything (or deny what can't be
// terminated)" posture — while an explicit per-entry mode token still wins. Unset/invalid keeps the
// inc1-compatible passthrough default (zero behaviour change when the knob is not set).
func TestDefaultEgressModeKnob(t *testing.T) {
	content := "api.host.com\n.example.com\n10.0.0.0/8\npin.host.com pinned\nplain.host.com passthrough\n*\n"
	t.Setenv("BULKHEAD_EGRESS_DEFAULT_MODE", "inspect")
	al, err := LoadAllowlist(writeFile(t, t.TempDir(), content))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ host, want string }{
		{"api.host.com", modeInspect},       // unmarked exact -> knob
		{"x.example.com", modeInspect},      // unmarked suffix -> knob
		{"10.1.2.3", modeInspect},           // unmarked cidr -> knob
		{"pin.host.com", modePinned},        // explicit pinned overrides the knob
		{"plain.host.com", modePassthrough}, // explicit passthrough overrides the knob
		{"other.host.com", modeInspect},     // falls to the unmarked "*" -> knob
	} {
		if got := al.Mode(c.host); got != c.want {
			t.Errorf("knob=inspect: Mode(%q)=%q want %q", c.host, got, c.want)
		}
	}

	// Unset -> the inc1-compatible passthrough default; an invalid value falls back the same way.
	for _, val := range []string{"", "bogus"} {
		t.Setenv("BULKHEAD_EGRESS_DEFAULT_MODE", val)
		al2, _ := LoadAllowlist(writeFile(t, t.TempDir(), "api.host.com\n"))
		if got := al2.Mode("api.host.com"); got != modePassthrough {
			t.Errorf("knob=%q: an unmarked entry must default to passthrough, got %q", val, got)
		}
	}
}

func TestProvisionCARoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := provisionCA(dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"ca.key", "ca.crt", "agent-trust.crt"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
	}
	if fi, _ := os.Stat(filepath.Join(dir, "ca.key")); fi != nil && fi.Mode().Perm() != 0o600 {
		t.Errorf("ca.key perms = %v, want 0600", fi.Mode().Perm())
	}
	// idempotent: a second provision keeps the SAME CA (rotating would invalidate live trust)
	crt1, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err := provisionCA(dir); err != nil {
		t.Fatal(err)
	}
	crt2, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if string(crt1) != string(crt2) {
		t.Error("provisionCA is not idempotent (CA changed on re-run)")
	}
	// agent-trust.crt carries the proxy CA
	trust, _ := os.ReadFile(filepath.Join(dir, "agent-trust.crt"))
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trust) {
		t.Fatal("agent-trust.crt has no usable certs")
	}
	if !caPresentValid(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")) {
		t.Error("caPresentValid false for a freshly provisioned CA")
	}
}

// TestLeafForVerifies proves the security-critical minting: a leaf chains to the CA, matches the
// CONNECT host, fails for a different host, is cached, and works for IP hosts.
func TestLeafForVerifies(t *testing.T) {
	m := testMITM(t)
	pool := x509.NewCertPool()
	pool.AddCert(m.cert)

	leaf, err := m.leafFor("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "api.example.com", Roots: pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("leaf does not verify for its host: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "evil.com", Roots: pool}); err == nil {
		t.Error("leaf wrongly verified for a different host")
	}
	if leaf2, _ := m.leafFor("api.example.com"); leaf2 != leaf {
		t.Error("leaf not cached (different pointer for same host)")
	}
	ipLeaf, err := m.leafFor("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ipCert, _ := x509.ParseCertificate(ipLeaf.Certificate[0])
	if _, err := ipCert.Verify(x509.VerifyOptions{DNSName: "127.0.0.1", Roots: pool}); err != nil {
		t.Fatalf("IP leaf does not verify: %v", err)
	}
}

// TestInspectRules exercises the sub-A content rules (pure logic, no TLS): byte cap, needle (incl.
// split across buffers via the sliding window), HTTP head parse + Host-coherence finding.
func TestInspectRules(t *testing.T) {
	allow := &Proxy{maxReqBytes: 100, denyNeedles: []string{"SECRET"}}

	st := &inspectState{host: "h.com"}
	if r := allow.inspect(st, []byte("GET / HTTP/1.1\r\nHost: h.com\r\n\r\n")); r != "" {
		t.Errorf("clean request: want allow, got deny %q", r)
	}
	if st.method != "GET" || st.path != "/" {
		t.Errorf("head parse wrong: method=%q path=%q", st.method, st.path)
	}

	if r := (&Proxy{denyNeedles: []string{"SECRET"}}).inspect(&inspectState{host: "h.com"}, []byte("x SECRET y")); r != "needle" {
		t.Errorf("needle: want deny, got %q", r)
	}

	if r := (&Proxy{maxReqBytes: 100}).inspect(&inspectState{host: "h.com"}, make([]byte, 200)); r != "req-byte-cap" {
		t.Errorf("byte cap: want deny, got %q", r)
	}

	// Host-header vs CONNECT-host mismatch -> recorded finding (not a deny in sub-A)
	st4 := &inspectState{host: "h.com"}
	if r := allow.inspect(st4, []byte("POST /x HTTP/1.1\r\nHost: evil.com\r\n\r\n")); r != "" {
		t.Errorf("host mismatch should not deny in sub-A, got %q", r)
	}
	if !strings.Contains(st4.reason, "host-mismatch") {
		t.Errorf("want host-mismatch finding, got reason=%q", st4.reason)
	}

	// a needle split across two buffers is caught by the sliding window
	pN := &Proxy{denyNeedles: []string{"ABCD"}}
	stN := &inspectState{host: "h.com"}
	pN.inspect(stN, []byte("zzzAB"))
	if r := pN.inspect(stN, []byte("CDzzz")); r != "needle" {
		t.Errorf("split needle: want deny, got %q", r)
	}
}

// TestInspectMethodAllowlist (ADR-0034 inc2 sub-B): the operator method-allowlist for inspected egress
// denies a request whose method is absent (the moment the head parses, before the body relays), and an
// empty allowlist imposes no restriction. The match is case-insensitive so a lowercase method cannot dodge it.
func TestInspectMethodAllowlist(t *testing.T) {
	if ms := methodSet("get, Head"); len(ms) != 2 || !ms["GET"] || !ms["HEAD"] {
		t.Fatalf("methodSet parse/uppercase wrong: %v", ms)
	}
	if methodSet("   ") != nil {
		t.Fatal("empty methodSet must be nil (no restriction)")
	}

	p := &Proxy{allowMethods: methodSet("GET,HEAD")}
	if r := p.inspect(&inspectState{host: "h.com"}, []byte("GET / HTTP/1.1\r\nHost: h.com\r\n\r\n")); r != "" {
		t.Errorf("GET in allowlist: want allow, got %q", r)
	}
	if r := p.inspect(&inspectState{host: "h.com"}, []byte("POST /x HTTP/1.1\r\nHost: h.com\r\n\r\n")); r != "method:POST" {
		t.Errorf("POST not in allowlist: want method deny, got %q", r)
	}
	if r := p.inspect(&inspectState{host: "h.com"}, []byte("post /x HTTP/1.1\r\nHost: h.com\r\n\r\n")); r != "method:post" {
		t.Errorf("lowercase post must still be denied (no case dodge), got %q", r)
	}
	// no allowlist => sub-A behaviour: any method is allowed through inspection.
	if r := (&Proxy{}).inspect(&inspectState{host: "h.com"}, []byte("POST /x HTTP/1.1\r\nHost: h.com\r\n\r\n")); r != "" {
		t.Errorf("no allowlist: POST must be allowed, got %q", r)
	}
}
