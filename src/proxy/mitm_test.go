//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
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

// TestInspectRequestRules exercises the per-request rule engine directly (pure, no TLS): the method
// allowlist (case-insensitive), the needle scan over the complete serialised request, and the byte cap.
func TestInspectRequestRules(t *testing.T) {
	mk := func(method string) *http.Request {
		r, _ := http.NewRequest(method, "https://h.com/x", nil)
		return r
	}
	p := &Proxy{allowMethods: methodSet("GET, head")}
	if r := p.inspectRequest(mk("GET"), []byte("GET /x HTTP/1.1\r\n\r\n"), 10); r != "" {
		t.Errorf("GET allowed: got deny %q", r)
	}
	if r := p.inspectRequest(mk("post"), []byte("post /x HTTP/1.1\r\n\r\n"), 10); r != "method:post" {
		t.Errorf("lowercase post must be denied case-insensitively, got %q", r)
	}
	if r := (&Proxy{}).inspectRequest(mk("DELETE"), []byte("DELETE /x HTTP/1.1\r\n\r\n"), 10); r != "" {
		t.Errorf("empty allowlist must not restrict, got %q", r)
	}
	if r := (&Proxy{denyNeedles: []string{"SECRET"}}).inspectRequest(mk("GET"), []byte("GET /x HTTP/1.1\r\nX: SECRET\r\n\r\n"), 10); r != "needle" {
		t.Errorf("needle in serialised request must deny, got %q", r)
	}
	if r := (&Proxy{maxReqBytes: 100}).inspectRequest(mk("GET"), []byte("..."), 101); r != "req-byte-cap" {
		t.Errorf("over-cap must deny, got %q", r)
	}
	if methodSet("  ") != nil || !methodSet("get,POST")["GET"] || !methodSet("get,POST")["POST"] {
		t.Errorf("methodSet uppercase/nil-on-empty wrong")
	}
}

// runInspect drives inspectRelay over net.Pipe: it writes requestBlob to the agent side and collects
// exactly the bytes the proxy FORWARDED upstream (the security-relevant observable — a denied or smuggled
// request must NOT appear there) plus the final verdict. A short idle timeout ends the request stream
// (net.Pipe has no CloseWrite to half-close with).
func runInspect(t *testing.T, p *Proxy, requestBlob string) (forwarded []byte, st *inspectState) {
	t.Helper()
	clientProxy, agent := net.Pipe()
	upstreamProxy, upstream := net.Pipe()
	p.idleTimeout = 250 * time.Millisecond
	p.tunnelMax = 3 * time.Second

	stCh := make(chan *inspectState, 1)
	go func() { stCh <- p.inspectRelay(clientProxy, upstreamProxy, "h.com", "443") }()

	var fwd bytes.Buffer
	upDone := make(chan struct{})
	go func() { // upstream: drain the forwarded requests; never respond (the response dir idles out)
		defer close(upDone)
		buf := make([]byte, 4096)
		for {
			_ = upstream.SetReadDeadline(time.Now().Add(time.Second))
			n, err := upstream.Read(buf)
			if n > 0 {
				fwd.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { // agent: send the request blob, then discard anything sent back
		_, _ = agent.Write([]byte(requestBlob))
		buf := make([]byte, 4096)
		for {
			_ = agent.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := agent.Read(buf); err != nil {
				return
			}
		}
	}()

	st = <-stCh
	_, _, _, _ = agent.Close(), upstream.Close(), clientProxy.Close(), upstreamProxy.Close()
	<-upDone
	return fwd.Bytes(), st
}

// TestInspectRelayPipelineBypass is the headline soundness test: the HTTP/1.1-pipelining bypass that sank
// the first method-allowlist attempt is closed. With INSPECT_METHODS=GET, an agent that pipelines a
// disallowed POST behind an allowed GET must have the POST DENIED and — critically — never forwarded.
func TestInspectRelayPipelineBypass(t *testing.T) {
	p := &Proxy{allowMethods: methodSet("GET")}
	blob := "GET /ok HTTP/1.1\r\nHost: h.com\r\n\r\n" +
		"POST /evil HTTP/1.1\r\nHost: h.com\r\nContent-Length: 5\r\n\r\nhello"
	fwd, st := runInspect(t, p, blob)
	if !bytes.Contains(fwd, []byte("GET /ok")) {
		t.Errorf("the allowed GET should have been forwarded; upstream got: %q", fwd)
	}
	if bytes.Contains(fwd, []byte("POST")) || bytes.Contains(fwd, []byte("/evil")) || bytes.Contains(fwd, []byte("hello")) {
		t.Fatalf("PIPELINING BYPASS: the disallowed POST reached upstream: %q", fwd)
	}
	if !st.denied || st.reason != "method:POST" {
		t.Errorf("want deny reason=method:POST, got denied=%v reason=%q", st.denied, st.reason)
	}
}

// TestInspectRelayChunkedNormalized: a chunked request body is re-serialised with canonical Content-Length
// framing upstream (the proxy normalises framing — the smuggling defense), and the flow is allowed.
func TestInspectRelayChunkedNormalized(t *testing.T) {
	fwd, st := runInspect(t, &Proxy{}, "POST /u HTTP/1.1\r\nHost: h.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
	if st.denied {
		t.Fatalf("clean chunked POST must be allowed, got deny %q", st.reason)
	}
	if !bytes.Contains(fwd, []byte("Content-Length: 5")) || bytes.Contains(fwd, []byte("chunked")) {
		t.Errorf("chunked body must be re-serialised as Content-Length (no chunked) upstream: %q", fwd)
	}
	if !bytes.Contains(fwd, []byte("hello")) {
		t.Errorf("the body should still reach upstream: %q", fwd)
	}
}

// TestInspectRelayMalformedFailsClosed: an ambiguous request (conflicting Content-Length, a classic
// smuggling vector) fails closed — denied by the parser, nothing forwarded.
func TestInspectRelayMalformedFailsClosed(t *testing.T) {
	fwd, st := runInspect(t, &Proxy{}, "GET /x HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nABCD")
	if !st.denied || st.reason != "malformed-request" {
		t.Errorf("conflicting Content-Length must fail closed, got denied=%v reason=%q", st.denied, st.reason)
	}
	if len(fwd) != 0 {
		t.Errorf("nothing should be forwarded for a malformed request, got %q", fwd)
	}
}

// TestInspectRelayNeedleInBody: a deny-needle anywhere in the request (here the body) is caught over the
// complete buffered request — TLS-record fragmentation cannot split it (the whole request is buffered).
func TestInspectRelayNeedleInBody(t *testing.T) {
	p := &Proxy{denyNeedles: []string{"SECRETTOKEN"}}
	fwd, st := runInspect(t, p, "POST /u HTTP/1.1\r\nHost: h.com\r\nContent-Length: 17\r\n\r\nxxSECRETTOKENxxxx")
	if !st.denied || st.reason != "needle" {
		t.Errorf("needle in body must deny, got denied=%v reason=%q", st.denied, st.reason)
	}
	if bytes.Contains(fwd, []byte("SECRETTOKEN")) {
		t.Errorf("a needle request must not reach upstream: %q", fwd)
	}
}
