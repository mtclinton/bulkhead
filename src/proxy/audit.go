// SPDX-License-Identifier: AGPL-3.0-only

// ADR-0034 / ADR-0017: the egress proxy's signed egress-decision audit chain. The egress
// pillar gets the same tamper-evident accountability the collector/broker/router already have:
// every egress decision (allow/deny + destination) is appended to an ed25519-signed, sha256
// hash-chained, domain-tagged ("egress-proxy") log, verified by the SAME
// `bulkhead-collector verify-audit`. Because the proxy is the SINGLE mediated egress path for a
// confined agent, this chain is a complete, non-repudiable record of every destination it reached.
//
// The proxy is a SEPARATE Go module, so the audit primitives are COPIED byte-for-byte from the
// collector/router (canonical() MUST stay byte-identical or the collector's verifier rejects these
// records). A golden vector is pinned in audit_test.go to catch drift in CI, identical to the one
// the router and collector pin. append() takes a mutex because handleConn runs concurrently.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// auditEvent is the proxy's overload of the six chained fields (mirrors the collector's provEvent).
type auditEvent struct {
	Comm     string
	Hook     string
	Decision string
	Mode     string
}

// durableFile is the subset of *os.File that append() uses, an interface so tests can inject
// I/O faults to exercise the transactional-append rollback. *os.File satisfies it.
type durableFile interface {
	Write([]byte) (int, error)
	Sync() error
	Truncate(int64) error
	Stat() (os.FileInfo, error)
	Close() error
}

type auditLog struct {
	mu       sync.Mutex // handleConn appends concurrently
	f        durableFile
	path     string
	priv     ed25519.PrivateKey
	prevHash []byte
	seq      uint64
	domain   string
}

// auditRecord is byte-identical to the collector's (the verifier unmarshals it); keep the json
// tags + the field set in sync with src/collector and src/router.
type auditRecord struct {
	Seq      uint64 `json:"seq"`
	TS       int64  `json:"ts"`
	CgroupID uint64 `json:"cgroup_id"`
	PID      uint32 `json:"pid"`
	Comm     string `json:"comm"`
	Hook     string `json:"hook"`
	Decision string `json:"decision"`
	Mode     string `json:"mode"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
	Sig      string `json:"sig"`
}

// openAuditLog opens (continuing across boots) the egress chain under $BULKHEAD_AUDIT_DIR. Mirrors
// the router's; the domain is "egress-proxy".
func openAuditLog(domain, filename string) (*auditLog, error) {
	dir := "/var/lib/bulkhead/audit-egress"
	if d := os.Getenv("BULKHEAD_AUDIT_DIR"); d != "" {
		dir = d
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	chainPath := filepath.Join(dir, filename)
	prev := make([]byte, sha256.Size)
	if h := lastChainHash(chainPath); h != nil {
		prev = h
	}
	f, err := os.OpenFile(chainPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	priv, err := loadSigningKey()
	if err != nil {
		f.Close()
		return nil, err
	}
	a := &auditLog{f: f, path: f.Name(), priv: priv, prevHash: prev, domain: domain}
	if err := os.WriteFile(filepath.Join(dir, "audit-pub.txt"), []byte(a.pubHex()+"\n"), 0o644); err != nil {
		log.Printf("audit: export public key: %v", err)
	}
	return a, nil
}

// loadSigningKey reads the 32-byte Ed25519 seed from CREDENTIALS_DIRECTORY/audit-seed (the TPM-sealed
// seed shared with the collector/broker/router, ADR-0008; domain separation keeps the proxy's records
// distinct). Absent a credential it falls back to an ephemeral per-boot key so dev still signs+verifies
// (via the exported audit-pub.txt) — UNLESS BULKHEAD_REQUIRE_SEALED_KEY=1, then it fails closed.
func loadSigningKey() (ed25519.PrivateKey, error) {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		if seed, err := os.ReadFile(filepath.Join(dir, "audit-seed")); err == nil && len(seed) >= ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]), nil
		}
	}
	if os.Getenv("BULKHEAD_REQUIRE_SEALED_KEY") == "1" {
		return nil, fmt.Errorf("sealed audit key unavailable (CREDENTIALS_DIRECTORY=%q): refusing to sign with an ephemeral key",
			os.Getenv("CREDENTIALS_DIRECTORY"))
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func (a *auditLog) pubHex() string {
	return hex.EncodeToString(a.priv.Public().(ed25519.PublicKey))
}

// canonical is a fixed-order, length-prefixed binary encoding of exactly the chained fields. It MUST
// stay byte-identical to src/collector and src/router — the collector's verify-audit recomputes it.
// The domain is bound in first, so a record signed for one chain can never verify as another's.
func canonical(r auditRecord, prev []byte, domain string) []byte {
	var b bytes.Buffer
	var u8 [8]byte
	put := func(v uint64) { binary.BigEndian.PutUint64(u8[:], v); b.Write(u8[:]) }
	putStr := func(s string) { put(uint64(len(s))); b.WriteString(s) }
	putStr(domain)
	put(r.Seq)
	put(uint64(r.TS))
	put(r.CgroupID)
	put(uint64(r.PID))
	putStr(r.Comm)
	putStr(r.Hook)
	putStr(r.Decision)
	putStr(r.Mode)
	put(uint64(len(prev)))
	b.Write(prev)
	return b.Bytes()
}

// lastChainHash returns the decoded Hash of the last well-formed record (the tip), or nil. Byte-
// identical to the collector's so cross-boot continuation links correctly.
func lastChainHash(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		ln := bytes.TrimSpace(lines[i])
		if len(ln) == 0 {
			continue
		}
		var r auditRecord
		if json.Unmarshal(ln, &r) != nil {
			return nil
		}
		h, err := hex.DecodeString(r.Hash)
		if err != nil || len(h) != sha256.Size {
			return nil
		}
		return h
	}
	return nil
}

// append signs one record and appends it, under the mutex. Transactional: in-memory chain state is
// advanced ONLY after the record is durable, and a Write/Sync failure truncates the partial tail back
// to the pre-append EOF — so a transient I/O error never leaves a gapped seq or forked prev_hash (either
// of which would fail-close the verify-audit boot gate on the next boot with no self-repair).
func (a *auditLog) append(ev auditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	nextSeq := a.seq + 1
	r := auditRecord{
		Seq: nextSeq, TS: time.Now().UnixNano(),
		Comm: ev.Comm, Hook: ev.Hook, Decision: ev.Decision, Mode: ev.Mode,
		PrevHash: hex.EncodeToString(a.prevHash),
	}
	// Coerce the chained string fields to valid UTF-8 BEFORE signing (json.Marshal replaces ill-formed
	// UTF-8 with U+FFFD on write, so a raw-byte signature over invalid UTF-8 would never re-verify). For
	// valid UTF-8 it is a no-op; done here (not in canonical()) to keep canonical() byte-identical.
	r.Comm = strings.ToValidUTF8(r.Comm, "�")
	r.Hook = strings.ToValidUTF8(r.Hook, "�")
	r.Decision = strings.ToValidUTF8(r.Decision, "�")
	r.Mode = strings.ToValidUTF8(r.Mode, "�")
	sum := sha256.Sum256(canonical(r, a.prevHash, a.domain))
	r.Hash = hex.EncodeToString(sum[:])
	r.Sig = hex.EncodeToString(ed25519.Sign(a.priv, sum[:]))

	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	fi, err := a.f.Stat()
	if err != nil {
		return err
	}
	off := fi.Size()
	if _, err := a.f.Write(append(line, '\n')); err != nil {
		a.rollback(off)
		return err
	}
	if err := a.f.Sync(); err != nil {
		a.rollback(off)
		return err
	}
	a.seq = nextSeq // commit the in-memory tip ONLY now that the record is durable
	a.prevHash = sum[:]
	return nil
}

// rollback drops any bytes written past off so a failed/partial record never strands on disk to gap or
// fork the chain; append() leaves a.seq/a.prevHash uncommitted, so a clean retry re-appends from off.
func (a *auditLog) rollback(off int64) {
	if err := a.f.Truncate(off); err != nil {
		log.Printf("audit: rollback truncate to %d: %v", off, err)
	}
}

func (a *auditLog) Close() error { return a.f.Close() }

// maxAuditDstLen caps the destination string written into each signed record. The host is already
// validated (<=253) by readRequest, so this is a defensive belt bounding chain growth.
const maxAuditDstLen = 260

// recordEgress overloads the six chained fields onto one egress decision: Hook="connect",
// Decision="allow"|"deny", Mode carries "dst=host:port" + an optional reason. One signed,
// non-repudiable record per decision — the single mediated chokepoint becomes a tamper-evident
// log of every destination a confined agent reached. The caller fail-closes the ALLOW path on a
// failed append (no un-audited byte leaves), as the router does record-before-route.
func (a *auditLog) recordEgress(host, port, decision, reason string) error {
	dst := host
	if port != "" {
		dst = host + ":" + port
	}
	if len(dst) > maxAuditDstLen {
		cut := maxAuditDstLen
		for cut > 0 && !utf8.RuneStart(dst[cut]) {
			cut--
		}
		dst = dst[:cut] + "...(truncated)"
	}
	mode := "dst=" + dst
	if reason != "" {
		mode += " reason=" + reason
	}
	return a.append(auditEvent{Comm: "egress-proxy", Hook: "connect", Decision: decision, Mode: mode})
}
