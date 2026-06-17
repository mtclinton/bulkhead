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
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
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
	cache map[string]*tls.Certificate // CONNECT host -> minted leaf (bounded by maxLeafCache)
}

// maxLeafCache bounds the per-host leaf-cert cache. Without it, a confined agent fetching unbounded
// DISTINCT allowed hostnames — especially under BULKHEAD_EGRESS_DEFAULT_MODE=inspect, where every
// allowed host is terminated and thus minted a leaf — grows the cache without limit (a slow memory
// leak). When full, leafFor evicts one arbitrary entry before inserting; an evicted-but-still-needed
// host simply re-mints (~1ms), so this buys a hard memory ceiling for at most an occasional re-sign,
// never any correctness loss. A var (not const) so tests can shrink it. ~1KB/leaf => ~1MB at 1024.
var maxLeafCache = 1024

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
	// Bounded insert: only evict when adding a genuinely NEW host that would exceed the cap (Go's map
	// range is randomized, so the victim is arbitrary — fine, since a re-mint is cheap).
	if _, exists := m.cache[host]; !exists && len(m.cache) >= maxLeafCache {
		for k := range m.cache {
			delete(m.cache, k)
			break
		}
	}
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
	// ALPN is pinned to http/1.1 on BOTH legs so the inspected stream is always HTTP/1.1 framing the
	// proxy fully parses (sub-A scope). An agent that insists on h2 gets no h2 ALPN here and so speaks
	// http/1.1; if it forces h2 anyway the request parse fails and the flow fails closed (R4), never
	// relayed un-inspected.
	clientTLS := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
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
	upstreamTLS := tls.Client(up, &tls.Config{ServerName: host, RootCAs: p.realRoots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
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

// inspectState carries one terminated flow's metadata + counters. The two relay goroutines touch
// disjoint fields (the agent->upstream goroutine owns method/path/reqBytes/denied/reason; the
// upstream->agent goroutine owns respBytes), and the final record is read only after wg.Wait(), so no
// lock is needed. method/path hold the FIRST request's line (the per-flow signed record's granularity).
type inspectState struct {
	host      string
	method    string
	path      string
	reqBytes  int64
	respBytes int64
	denied    bool
	reason    string
}

// maxInspectBody hard-bounds how much of a single request body the proxy buffers when maxReqBytes is
// unset (production sets it to 1<<20), so a missing knob can never turn the buffering relay into an
// unbounded-memory sink.
const maxInspectBody = 8 << 20

// inspectRelay relays a TLS-terminated flow while keeping the agent->upstream direction HTTP/1.1-AWARE:
// it PARSES each request, vets it whole against the request-side rule engine, and RE-SERIALISES it to the
// upstream with canonical fixed-length framing. So the upstream's request boundaries are exactly the
// proxy's — never the agent's raw bytes — which forecloses the request-smuggling / HTTP/1.1-pipelining
// class that sank the first method-allowlist attempt (a rule on a one-shot first-line parse was bypassed
// by pipelining a second request behind an allowed one; here EVERY request is framed and gated). Nothing
// reaches the upstream until the WHOLE request is vetted (no partial-request leak; the needle scan sees
// the complete request). The response direction stays a counted opaque relay (response inspection is a
// later sub-B item). Idle/total deadlines + CloseWrite match splice() so a terminated flow cannot pin a
// slot longer than a spliced one. A request the HTTP/1.1 parser cannot frame (garbage, ambiguous
// smuggling framing, or a post-Upgrade/h2 byte stream) fails CLOSED (R4), never relayed un-inspected.
func (p *Proxy) inspectRelay(clientTLS, upstreamTLS net.Conn, host, port string) *inspectState {
	st := &inspectState{host: host}
	deadline := time.Now().Add(p.tunnelMax)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() { // agent -> upstream: HTTP/1.1-aware, sound framing
		defer wg.Done()
		defer closeWrite(upstreamTLS)
		br := bufio.NewReader(&idleConn{Conn: clientTLS, idle: p.idleTimeout, total: deadline})
		first := true
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				if !isStreamEnd(err) {
					st.denied, st.reason = true, "malformed-request"
				}
				return
			}
			// Buffer the body (bounded), then re-serialise the WHOLE request with canonical fixed-length
			// framing — dropping the agent's chunked/ambiguous framing — into one buffer we vet then forward.
			body, capped := p.readInspectBody(req.Body)
			req.Body.Close()
			if capped {
				st.denied, st.reason = true, "req-byte-cap"
				return
			}
			req.Body = io.NopCloser(bytes.NewReader(body))
			req.ContentLength = int64(len(body))
			req.TransferEncoding = nil
			req.RequestURI = "" // required: req.Write writes from req.URL, not a server-side RequestURI
			var out bytes.Buffer
			if err := req.Write(&out); err != nil {
				return // cannot canonically re-serialise -> drop rather than forward something ambiguous
			}
			st.reqBytes += int64(out.Len())
			if first {
				st.method, st.path, first = req.Method, req.URL.RequestURI(), false
			}
			// Host-header vs CONNECT-host coherence: a confused-deputy SIGNAL, recorded (sub-A semantics),
			// not a deny (a legitimate virtual-host Host can differ from the CONNECT name).
			if h := stripPort(req.Host); h != "" && !strings.EqualFold(h, st.host) && st.reason == "" {
				st.reason = "finding:host-mismatch(" + h + ")"
			}
			if reason := p.inspectRequest(req, out.Bytes(), st.reqBytes); reason != "" {
				st.denied, st.reason = true, reason
				return
			}
			_ = upstreamTLS.SetWriteDeadline(deadline)
			if _, err := upstreamTLS.Write(out.Bytes()); err != nil {
				return
			}
		}
	}()

	go func() { // upstream -> agent (counted; response-direction inspection is a later sub-B item)
		defer wg.Done()
		defer closeWrite(clientTLS)
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
	return st
}

// inspectRequest applies the request-side rule engine to one fully-parsed, re-serialised inspected
// request (`serialized` is exactly the bytes about to go upstream; `reqBytes` is the cumulative flow
// total) and returns a deny reason ("" = allow). Because every request is framed by the proxy, these
// rules CANNOT be bypassed by pipelining or smuggling:
//   - method allowlist (inc2 sub-B): a method outside BULKHEAD_EGRESS_INSPECT_METHODS is denied,
//     case-insensitively (a lowercase "post" cannot dodge a POST rule). Empty allowlist => no restriction.
//   - per-flow byte cap: the cumulative request bytes bound bulk exfil to an allowed endpoint.
//   - operator literal needle denylist over the COMPLETE serialised request — no rolling window needed,
//     since the whole request is in `serialized`, so a needle can never split across reads.
func (p *Proxy) inspectRequest(req *http.Request, serialized []byte, reqBytes int64) string {
	if len(p.allowMethods) > 0 && !p.allowMethods[strings.ToUpper(req.Method)] {
		return "method:" + req.Method
	}
	if p.maxReqBytes > 0 && reqBytes > p.maxReqBytes {
		return "req-byte-cap"
	}
	for _, nd := range p.denyNeedles {
		if bytes.Contains(serialized, []byte(nd)) {
			return "needle"
		}
	}
	return ""
}

// readInspectBody buffers a request body up to the byte cap (maxReqBytes, else a hard memory bound), so
// the whole request can be vetted before any byte leaves. capped=true means the body alone exceeded the
// cap — a bulk-exfil signal the caller denies (req-byte-cap).
func (p *Proxy) readInspectBody(body io.Reader) (data []byte, capped bool) {
	limit := p.maxReqBytes
	if limit <= 0 || limit > maxInspectBody {
		limit = maxInspectBody
	}
	data, _ = io.ReadAll(io.LimitReader(body, limit+1))
	if int64(len(data)) > limit {
		return data[:limit], true
	}
	return data, false
}

// methodSet parses a comma-list of HTTP methods into an UPPERCASE set so a lowercase method cannot dodge
// a rule. Empty input => nil (no method restriction; the default). inc2 sub-B.
func methodSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, m := range strings.Split(s, ",") {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
			out[m] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// idleConn bounds every Read with a fresh idle deadline capped by an absolute total deadline, so
// http.ReadRequest (and the body reads behind it) over a terminated TLS conn honour the same idle/total
// budget as a spliced tunnel — a slow or stalled request stream cannot pin a concurrency slot.
type idleConn struct {
	net.Conn
	idle  time.Duration
	total time.Time
}

func (ic *idleConn) Read(b []byte) (int, error) {
	now := time.Now()
	if !now.Before(ic.total) {
		return 0, os.ErrDeadlineExceeded
	}
	rd := now.Add(ic.idle)
	if rd.After(ic.total) {
		rd = ic.total
	}
	_ = ic.Conn.SetReadDeadline(rd)
	return ic.Conn.Read(b)
}

// isStreamEnd reports whether err is a clean end of the agent's request stream (EOF, a hit deadline, or a
// closed conn) — the agent simply stopped sending. Any OTHER http.ReadRequest error is unparseable or
// ambiguous framing and is treated as a deny (fail closed), never a silent clean end.
func isStreamEnd(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, net.ErrClosed)
}

// closeWrite half-closes the write side after a relay direction drains (matches splice()).
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
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
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// The confined agent is a non-root DynamicUser and reads agent-trust.crt here at TLS time, so
	// the whole dir chain must be traversable by "other". MkdirAll leaves a pre-existing parent's
	// mode untouched (/data/bulkhead is created restrictively by the seal service), so relax it
	// explicitly. ca.key stays 0600 below — the secret is protected by the FILE mode, not the dir.
	_ = os.Chmod(filepath.Dir(dir), 0o755) // /data/bulkhead
	_ = os.Chmod(dir, 0o755)               // /data/bulkhead/mitm-ca
	sealMode := envOr("BULKHEAD_SEAL_KEY", "plain")
	keyPath := filepath.Join(dir, "ca.key")
	credPath := filepath.Join(dir, "ca.key.cred")
	crtPath := filepath.Join(dir, "ca.crt")
	trustPath := filepath.Join(dir, "agent-trust.crt")
	// Idempotent: a present+valid CA is kept (rotating it would invalidate live agent trust + any
	// minted leaves). "Valid" = the cert is unexpired AND its private key is available in the mode's
	// storage form: plaintext ca.key (plain) or a decryptable ca.key.cred (tpm2).
	if certValid(crtPath) && keyAvailable(sealMode, keyPath, credPath) {
		return writeAgentTrust(crtPath, trustPath)
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
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	if err := os.WriteFile(crtPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	// Deliver the private key per mode. tpm2 (bare metal): TPM2-seal it to ca.key.cred (PCR-bound,
	// decryptable only on the expected boot) and NEVER persist plaintext — the proxy loads it via
	// LoadCredentialEncrypted. plain (VM/dev): plaintext 0600 ca.key via LoadCredential. Same
	// pattern as the audit seed (bulkhead-seal-audit-key); qemu vTPM sealing is unreliable, so plain
	// is the VM default and tpm2 is the bare-metal posture.
	if sealMode == "tpm2" {
		_ = os.Remove(keyPath)
		if err := sealKeyTPM2(keyPEM, credPath); err != nil {
			return fmt.Errorf("tpm2-seal CA key: %w", err)
		}
	} else {
		_ = os.Remove(credPath)
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return err
		}
	}
	return writeAgentTrust(crtPath, trustPath)
}

// certValid reports whether crtPath holds an unexpired certificate.
func certValid(crtPath string) bool {
	crtPEM, err := os.ReadFile(crtPath)
	if err != nil {
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

// keyAvailable reports whether the CA private key is present in the storage form for sealMode:
// a decryptable ca.key.cred (tpm2) or a plaintext ca.key (plain).
func keyAvailable(sealMode, keyPath, credPath string) bool {
	if sealMode == "tpm2" {
		return sealedKeyDecrypts(credPath)
	}
	_, err := os.Stat(keyPath)
	return err == nil
}

// sealedKeyDecrypts reports whether credPath is a TPM2-sealed cred that unseals to a parseable
// Ed25519 PKCS#8 key on THIS boot (the idempotence + post-seal integrity check).
func sealedKeyDecrypts(credPath string) bool {
	if _, err := os.Stat(credPath); err != nil {
		return false
	}
	out, err := exec.Command("systemd-creds", "decrypt", "--name=mitm-ca-key", credPath, "-").Output()
	if err != nil {
		return false
	}
	cb, _ := pem.Decode(out)
	if cb == nil {
		return false
	}
	k, err := x509.ParsePKCS8PrivateKey(cb.Bytes)
	if err != nil {
		return false
	}
	_, ok := k.(ed25519.PrivateKey)
	return ok
}

// sealKeyTPM2 TPM2-seals keyPEM to credPath (named "mitm-ca-key", PCR-bound) via systemd-creds —
// the same tool the audit seed uses — and verifies it unseals back, failing closed otherwise.
func sealKeyTPM2(keyPEM []byte, credPath string) error {
	pcrs := envOr("BULKHEAD_SEAL_PCRS", "7")
	tmp := credPath + ".tmp"
	_ = os.Remove(tmp)
	cmd := exec.Command("systemd-creds", "encrypt", "--name=mitm-ca-key", "--with-key=tpm2", "--tpm2-pcrs="+pcrs, "-", tmp)
	cmd.Stdin = bytes.NewReader(keyPEM)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("systemd-creds encrypt: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if !sealedKeyDecrypts(tmp) {
		_ = os.Remove(tmp)
		return fmt.Errorf("sealed cred does not unseal back to an Ed25519 key")
	}
	_ = os.Chmod(tmp, 0o600)
	return os.Rename(tmp, credPath)
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
