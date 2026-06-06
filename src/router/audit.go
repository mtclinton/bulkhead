// SPDX-License-Identifier: AGPL-3.0-only

// ADR-0027: the router's signed routing-decision audit chain. The model-ROUTING pillar gets the same
// tamper-evident accountability the collector/broker already have (ADR-0017): every routing decision is
// appended to an ed25519-signed, sha256 hash-chained, domain-tagged ("router") log, verified by the SAME
// `bulkhead-collector verify-audit` (ADR-0026 no-rewind verdict included).
//
// The router is a SEPARATE Go module, so the audit primitives are COPIED byte-for-byte from the collector
// (src/collector/main.go) rather than imported — canonical() MUST stay byte-identical or the collector's
// verifier rejects router records, so a golden vector is pinned in BOTH modules (audit_test.go) to catch
// drift in CI. Two router-specific changes vs the collector copy: (1) append() takes a mutex (the router's
// HTTP handlers run CONCURRENTLY, unlike the collector's single event loop); (2) recordRoute overloads the
// six record fields onto a routing decision, exactly as the broker's recordDecision overloads them.
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

// auditEvent is the router's overload of the six chained fields (mirrors the collector's provEvent).
type auditEvent struct {
	Comm     string
	Hook     string
	Decision string
	Mode     string
}

type auditLog struct {
	mu       sync.Mutex // router-specific: concurrent HTTP handlers append; collector/broker are single-writer
	f        *os.File
	path     string
	priv     ed25519.PrivateKey
	prevHash []byte
	seq      uint64
	domain   string
}

// auditRecord is byte-identical to the collector's (the verifier unmarshals it); keep the json tags + the
// field set in sync with src/collector/main.go.
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

// openAuditLog opens (continuing across boots, F5) the router chain under $BULKHEAD_AUDIT_DIR. Mirrors the
// collector's openAuditLog; the domain is "router".
func openAuditLog(domain, filename string) (*auditLog, error) {
	dir := "/var/lib/bulkhead/audit-router"
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
	// Export the public key beside the chain so it can be verified OFFLINE (`verify-audit <chain>` resolves
	// it via the sibling audit-pub.txt when no sealed seed / explicit key is supplied).
	if err := os.WriteFile(filepath.Join(dir, "audit-pub.txt"), []byte(a.pubHex()+"\n"), 0o644); err != nil {
		log.Printf("audit: export public key: %v", err)
	}
	return a, nil
}

// loadSigningKey reads the 32-byte Ed25519 seed from the systemd credential dir (CREDENTIALS_DIRECTORY/
// audit-seed — the TPM-sealed seed shared with the collector/broker, ADR-0008; domain separation keeps the
// router's records distinct). Absent a credential it falls back to an ephemeral per-boot key so the
// Buildroot/dev smoke test still signs+verifies (via the exported audit-pub.txt) — UNLESS
// BULKHEAD_REQUIRE_SEALED_KEY=1, in which case it fails closed rather than signing with a throwaway key.
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

// canonical is a fixed-order, length-prefixed binary encoding of exactly the chained fields. It MUST stay
// byte-identical to src/collector/main.go's canonical() — the collector's verify-audit recomputes it over
// router records. The "router" domain (F4) is bound in first, so a record signed for one chain can never
// verify as another's.
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

// lastChainHash returns the decoded Hash of the last well-formed record (the tip), or nil. Byte-identical
// to the collector's so cross-boot continuation links correctly.
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

// append signs one record and appends it, under the mutex (the router's handlers are concurrent). A single
// write()+Sync() per record (atomic vs a concurrent reader; durable) — the LLM hot path dwarfs the fsync.
func (a *auditLog) append(ev auditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seq++
	r := auditRecord{
		Seq: a.seq, TS: time.Now().UnixNano(),
		Comm: ev.Comm, Hook: ev.Hook, Decision: ev.Decision, Mode: ev.Mode,
		PrevHash: hex.EncodeToString(a.prevHash),
	}
	// Coerce the chained string fields to valid UTF-8 BEFORE signing. json.Marshal replaces ill-formed
	// UTF-8 with U+FFFD on write, so a raw-byte signature over invalid UTF-8 (e.g. an untrusted client
	// model name split mid-rune by the cap) would never re-verify after the JSON round-trip and the boot
	// gate would fail CLOSED on a self-inconsistent record (a remote brick). Coercing here (not in
	// canonical()) keeps canonical() byte-identical with the collector; for valid UTF-8 it is a no-op.
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
	if _, err := a.f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := a.f.Sync(); err != nil {
		return err
	}
	a.prevHash = sum[:]
	return nil
}

func (a *auditLog) Close() error { return a.f.Close() }

// maxAuditModelLen caps the UNTRUSTED client model string written into each signed record. The router is
// network-facing; without this cap a flood of requests carrying an oversized model field (up to the 8 MiB
// body limit) would grow the audit chain unboundedly and exhaust the disk (DoS). The cap bounds the audit
// EVIDENCE only — the full model still drives routing/provider selection/proxying, and promptlen records
// the true request size regardless — so accountability is preserved while the growth vector is closed.
const maxAuditModelLen = 200

// recordRoute overloads the six chained fields onto a routing decision (the broker's recordDecision is the
// precedent): Hook="route", Decision=the route (local|api), Mode carries the reason + request evidence
// (model + prompt length, and the chosen paid provider for an api route — the outbound destination that
// received the prompt). One signed, non-repudiable record per routing decision.
func (a *auditLog) recordRoute(route, reason, model string, promptLen int, provider string) error {
	if len(model) > maxAuditModelLen {
		// Truncate on a rune boundary at or before the byte cap: keeps the DoS byte-bound (the cap exists
		// to bound chain growth from a flood) AND valid UTF-8, so a multi-byte rune is never split mid-way
		// (which append() would otherwise coerce to U+FFFD in the signed evidence).
		cut := maxAuditModelLen
		for cut > 0 && !utf8.RuneStart(model[cut]) {
			cut--
		}
		model = model[:cut] + "...(truncated)"
	}
	mode := fmt.Sprintf("reason=%s model=%s promptlen=%d", reason, model, promptLen)
	if provider != "" {
		mode += " provider=" + provider
	}
	return a.append(auditEvent{Comm: "router", Hook: "route", Decision: route, Mode: mode})
}
