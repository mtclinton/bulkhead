//go:build linux

// ADR-0034 increment 2: TLS-termination + content inspection. For an allowlist entry marked
// `inspect`, the proxy stops splicing opaque TLS and instead becomes the agent's TLS peer —
// presenting a leaf for the CONNECT host signed by an on-device re-signing CA the confined agent
// trusts — while separately handshaking the REAL upstream with full Web-PKI verification (so the
// MITM never downgrades the authentication the agent gave up). Decrypted agent->upstream bytes pass
// through an inspection hook before relay; every flow's content verdict is signed into the audit
// chain, and every NON-terminated flow is recorded as an explicit uninspected channel, so the chain
// is an honest coverage ledger. The single-canonical-parse invariant holds: the leaf and the dial
// both key off the CONNECT host (proxy.go), never the TLS SNI (a logged cross-check only).
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// --- the re-signing CA + leaf minting ---

// mitmCA holds the proxy's re-signing CA and a per-host leaf-cert cache. Holding this key is the
// power to forge any identity the agent trusts, so its custody mirrors the audit seed: generated
// on-device (bulkhead-provision-mitm-ca, never in the image/SBOM/RAUC), delivered as a systemd
// credential, plaintext-on-/data in the VM phase and TPM-sealed on bare metal (sub-B).
type mitmCA struct {
	cert    *x509.Certificate
	key     ed25519.PrivateKey
	leafKey ed25519.PrivateKey // one shared leaf key; per-host certs differ only by name/SAN
	leafPub ed25519.PublicKey

	mu    sync.Mutex
	cache map[string]*tls.Certificate // CONNECT host -> minted leaf
}

// loadMITMCA reads the CA cert+key from CREDENTIALS_DIRECTORY (mitm-ca-crt, mitm-ca-key), exactly as
// loadSigningKey reads the audit seed. With BULKHEAD_REQUIRE_MITM_CA=1 a missing/garbled CA fails
// CLOSED (the proxy refuses to start, so an inspect-marked TLS flow is never spliced uninspected).
// Otherwise it returns (nil, nil): the proxy runs as a pure inc1 boundary and inspect-marked flows
// fall through to an explicit passthrough record.
func loadMITMCA() (*mitmCA, error) {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	required := os.Getenv("BULKHEAD_REQUIRE_MITM_CA") == "1"
	crtPEM, errc := os.ReadFile(filepath.Join(dir, "mitm-ca-crt"))
	keyPEM, errk := os.ReadFile(filepath.Join(dir, "mitm-ca-key"))
	if dir == "" || errc != nil || errk != nil {
		if required {
			return nil, fmt.Errorf("re-signing CA unavailable (CREDENTIALS_DIRECTORY=%q): refusing to run with REQUIRE_MITM_CA=1", dir)
		}
		return nil, nil // no CA: inc1 passthrough-only mode
	}
	cert, key, err := parseCA(crtPEM, keyPEM)
	if err != nil {
		if required {
			return nil, fmt.Errorf("re-signing CA parse: %w", err)
		}
		return nil, nil
	}
	leafPub, leafPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &mitmCA{cert: cert, key: key, leafKey: leafPriv, leafPub: leafPub, cache: map[string]*tls.Certificate{}}, nil
}

func parseCA(crtPEM, keyPEM []byte) (*x509.Certificate, ed25519.PrivateKey, error) {
	cb, _ := pem.Decode(crtPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("CA cert: not a CERTIFICATE PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, fmt.Errorf("CA key: not a PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA key is not ed25519")
	}
	return cert, key, nil
}

// leafFor mints (and caches) a leaf cert for the CONNECT host, signed by the CA. The cert name is
// the host the agent CONNECTed to — the single canonical destination — never the TLS SNI.
func (m *mitmCA) leafFor(host string) (*tls.Certificate, error) {
	m.mu.Lock()
	if c, ok := m.cache[host]; ok {
		m.mu.Unlock()
		return c, nil
	}
	m.mu.Unlock()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour), // short-lived; re-minted across restarts
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.cert, m.leafPub, m.key)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: m.leafKey}
	m.mu.Lock()
	m.cache[host] = cert
	m.mu.Unlock()
	return cert, nil
}

// --- the terminate + inspect path ---

// terminate is the inc2 MITM path for an inspect-marked HTTPS destination. handleConn has already
// done the single parse, the allowlist check, the dial-time SSRF/metadata deny, and the
// record-before-act signed connect-ALLOW; `up` is the verified upstream TCP conn. Here we reply OK
// (the agent's proxyDial blocks on it before sending a ClientHello), handshake WITH the agent as the
// server, handshake the REAL upstream with full Web-PKI verification, then relay decrypted bytes
// through the inspection hook. Any handshake failure records a signed deny and drops — never splices.
func (p *Proxy) terminate(c, up net.Conn, host, port string) {
	if err := writeReply(c, "OK"); err != nil {
		return
	}
	leaf, err := p.mitm.leafFor(host)
	if err != nil {
		logd("MITM-FAIL", host, port, "leaf mint: "+err.Error())
		p.recordInspectDeny(host, port, "leaf-mint-fail")
		return
	}
	clientTLS := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12})
	if err := clientTLS.Handshake(); err != nil {
		logd("MITM-FAIL", host, port, "agent handshake: "+err.Error())
		p.recordInspectDeny(host, port, "tls-handshake-fail")
		return
	}
	defer clientTLS.Close()
	// SNI is a logged cross-check ONLY — the leaf and the dial both key off the CONNECT host, so a
	// spoofed SNI cannot re-interpret the destination (the single-parse invariant inc1 forecloses).
	if sni := clientTLS.ConnectionState().ServerName; sni != "" && !strings.EqualFold(sni, host) {
		logd("MITM-SNI", host, port, "SNI "+sni+" != CONNECT host (CONNECT host wins)")
	}
	upstreamTLS := tls.Client(up, &tls.Config{ServerName: host, RootCAs: p.realRoots, MinVersion: tls.VersionTLS12})
	if err := upstreamTLS.Handshake(); err != nil {
		logd("MITM-FAIL", host, port, "upstream verify: "+err.Error())
		p.recordInspectDeny(host, port, "upstream-verify-fail")
		return
	}
	defer upstreamTLS.Close()
	p.inspectRelay(clientTLS, upstreamTLS, host, port)
}

// recordInspectDeny signs a Hook=inspect deny for a flow that never relayed (handshake/leaf failure).
func (p *Proxy) recordInspectDeny(host, port, reason string) {
	if p.audit != nil {
		_ = p.audit.recordInspect(host, "", "", 0, 0, "deny", reason)
	}
}

// inspectState carries one terminated flow's parsed metadata + counters. The two relay goroutines
// touch disjoint fields (the agent->upstream goroutine owns method/path/reqBytes/denied/reason/the
// head buffer + needle window; the upstream->agent goroutine owns respBytes), and the final record
// is read only after wg.Wait(), so no lock is needed.
type inspectState struct {
	host      string
	method    string
	path      string
	reqHost   string
	reqBytes  int64
	respBytes int64
	denied    bool
	reason    string
	hdrParsed bool
	hdrBuf    []byte
	tail      []byte // sliding-window overlap so a needle can't split across buffers
}

const (
	maxHeadBytes = 8 << 10 // bound the request-head accumulation
	needleWindow = 256     // overlap kept between buffers for the needle scan
)

// inspectRelay relays decrypted bytes between agent and upstream — identical to splice() in its
// idle/total deadlines and CloseWrite half-close (a terminated flow cannot pin a concurrency slot
// longer than a spliced one) — except each agent->upstream buffer passes through p.inspect BEFORE it
// is written upstream, so a deny verdict drops the flow mid-stream. One signed Hook=inspect record is
// appended after the flow (the connect-ALLOW already fail-closed-gated the destination before any byte).
func (p *Proxy) inspectRelay(clientTLS, upstreamTLS net.Conn, host, port string) {
	st := &inspectState{host: host}
	deadline := time.Now().Add(p.tunnelMax)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() { // agent -> upstream (inspected)
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			now := time.Now()
			if !now.Before(deadline) {
				break
			}
			rd := now.Add(p.idleTimeout)
			if rd.After(deadline) {
				rd = deadline
			}
			_ = clientTLS.SetReadDeadline(rd)
			n, err := clientTLS.Read(buf)
			if n > 0 {
				if reason := p.inspect(st, buf[:n]); reason != "" {
					st.denied, st.reason = true, reason
					break
				}
				if _, werr := upstreamTLS.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if cw, ok := upstreamTLS.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()

	go func() { // upstream -> agent (counted; response-direction inspection is sub-B)
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			now := time.Now()
			if !now.Before(deadline) {
				break
			}
			rd := now.Add(p.idleTimeout)
			if rd.After(deadline) {
				rd = deadline
			}
			_ = upstreamTLS.SetReadDeadline(rd)
			n, err := upstreamTLS.Read(buf)
			if n > 0 {
				st.respBytes += int64(n)
				if _, werr := clientTLS.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if cw, ok := clientTLS.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()

	wg.Wait()
	decision, reason := "allow", st.reason
	if st.denied {
		decision, reason = "deny", st.reason
	}
	if p.audit != nil {
		_ = p.audit.recordInspect(host, st.method, st.path, st.reqBytes, st.respBytes, decision, reason)
	}
	logd("INSPECT", host, port, fmt.Sprintf("%s method=%s path=%s reqb=%d respb=%d %s",
		decision, st.method, st.path, st.reqBytes, st.respBytes, reason))
}

// inspect applies sub-A's small-but-real request-side ruleset to one decrypted agent->upstream
// buffer and returns a deny reason ("" = allow). Sub-A rules: (1) a per-flow byte budget bounding
// bulk exfil to an allowed endpoint; (2) Host-header vs CONNECT-host coherence (a confused-deputy
// signal within an allowed TLS session — RECORDED in sub-A, not yet a deny); (3) an operator literal
// needle denylist over a bounded sliding window so a match cannot split across buffers. Never logs
// the body; only the parsed head + counters + verdict reach the signed record.
func (p *Proxy) inspect(st *inspectState, buf []byte) string {
	st.reqBytes += int64(len(buf))
	if p.maxReqBytes > 0 && st.reqBytes > p.maxReqBytes {
		return "req-byte-cap"
	}
	if !st.hdrParsed {
		if len(st.hdrBuf) < maxHeadBytes {
			st.hdrBuf = append(st.hdrBuf, buf...)
		}
		if bytes.Contains(st.hdrBuf, []byte("\r\n\r\n")) || len(st.hdrBuf) >= maxHeadBytes {
			st.parseHead()
			if st.reqHost != "" && !strings.EqualFold(stripPort(st.reqHost), st.host) {
				st.reason = "finding:host-mismatch(" + stripPort(st.reqHost) + ")"
			}
		}
	}
	for _, nd := range p.denyNeedles {
		if bytes.Contains(append(st.tail, buf...), []byte(nd)) {
			return "needle"
		}
	}
	if len(buf) >= needleWindow {
		st.tail = append(st.tail[:0], buf[len(buf)-needleWindow:]...)
	} else {
		st.tail = append(st.tail[:0], buf...)
	}
	return ""
}

// parseHead extracts METHOD, request-target, and the Host header from the accumulated HTTP/1.1
// request head (sub-A scopes inspection to HTTP/1.1 request semantics; HTTP/2 is sub-B).
func (st *inspectState) parseHead() {
	st.hdrParsed = true
	lines := bytes.Split(st.hdrBuf, []byte("\r\n"))
	if len(lines) == 0 {
		return
	}
	if parts := bytes.Fields(lines[0]); len(parts) >= 2 {
		st.method = string(parts[0])
		st.path = string(parts[1])
	}
	for _, ln := range lines[1:] {
		if len(ln) == 0 {
			break // end of headers
		}
		if i := bytes.IndexByte(ln, ':'); i > 0 && bytes.EqualFold(bytes.TrimSpace(ln[:i]), []byte("host")) {
			st.reqHost = string(bytes.TrimSpace(ln[i+1:]))
			break
		}
	}
}

func stripPort(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// --- the on-device CA provisioning subcommand (bulkhead-egress-proxy --provision-ca <dir>) ---

// provisionCA generates the re-signing CA ON-DEVICE into dir (idempotent: a present+valid CA is kept,
// since rotating it would invalidate live trust): ca.key (0600), ca.crt, and agent-trust.crt
// (ca.crt ++ the system Web-PKI roots) — the single augmented bundle the confined agent trusts, so
// inspect-marked leaves verify against the proxy CA AND passthrough upstreams verify against the real
// roots, with no per-destination logic in the agent. Mirrors bulkhead-seal-audit-key's first-boot
// idempotence; the unique-per-appliance CA is never in the repo/SBOM/RAUC bundle.
func provisionCA(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	keyPath := filepath.Join(dir, "ca.key")
	crtPath := filepath.Join(dir, "ca.crt")
	trustPath := filepath.Join(dir, "agent-trust.crt")
	if caPresentValid(crtPath, keyPath) {
		return writeAgentTrust(crtPath, trustPath) // refresh the bundle; keep the CA
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "bulkhead egress-proxy re-signing CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(crtPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	return writeAgentTrust(crtPath, trustPath)
}

func caPresentValid(crtPath, keyPath string) bool {
	crtPEM, err := os.ReadFile(crtPath)
	if err != nil {
		return false
	}
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	cb, _ := pem.Decode(crtPEM)
	if cb == nil {
		return false
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return false
	}
	return time.Now().Before(cert.NotAfter)
}

// writeAgentTrust writes agent-trust.crt = {proxy CA} ++ {system Web-PKI roots}.
func writeAgentTrust(crtPath, trustPath string) error {
	ca, err := os.ReadFile(crtPath)
	if err != nil {
		return err
	}
	bundle := append([]byte{}, ca...)
	if !bytes.HasSuffix(bundle, []byte("\n")) {
		bundle = append(bundle, '\n')
	}
	if roots := systemRootsPEM(); len(roots) > 0 {
		bundle = append(bundle, roots...)
	}
	return os.WriteFile(trustPath, bundle, 0o644)
}

// systemRootsPEM returns the host's Web-PKI root bundle (ca-certificates), or nil. The provision
// service does not set SSL_CERT_FILE (only the confined jail does), so the standard paths are safe.
func systemRootsPEM() []byte {
	for _, p := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"} {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			return b
		}
	}
	return nil
}
