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
	"sort"
	"strconv"
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

// durableFile is the subset of *os.File that append() uses. It is an interface (not *os.File directly) so
// tests can inject I/O faults — a Write or Sync that errors — to exercise the transactional-append rollback
// in append(). *os.File satisfies it, so production behavior is unchanged.
type durableFile interface {
	Write([]byte) (int, error)
	Sync() error
	Truncate(int64) error
	Stat() (os.FileInfo, error)
	Close() error
}

type auditLog struct {
	mu       sync.Mutex // router-specific: concurrent HTTP handlers append; collector/broker are single-writer
	f        durableFile
	path     string
	priv     ed25519.PrivateKey
	prevHash []byte
	seq      uint64
	domain   string
	// ADR-0040 segment rotation (all guarded by a.mu, set once in openAuditLog except segNext, bumped by
	// rotate()). dir/base locate the chain; rotateBytes>0 enables rotation; segKeep is the retained window.
	dir         string
	base        string
	rotateBytes int64
	segKeep     int
	segNext     uint64
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
	// Discard an un-acked partial final record (a power-loss can leave append's "line\n" without its
	// '\n'); else O_APPEND fuses the next record onto the fragment, false-bricking verify-audit two
	// boots later. Best-effort. (Cross-cutting audit 2026-06-16; mirrors the collector's repair.)
	if err := repairTornTail(chainPath); err != nil {
		log.Printf("audit: torn-tail repair (%s): %v", chainPath, err)
	}
	// Seed the cross-boot prevHash (F5) from the chain TIP, which after a rotation lives in the live file
	// OR — in the rename->first-append window — the newest sealed segment (lastChainTip, ADR-0040), never a
	// spurious genesis that would fork the chain.
	prev := make([]byte, sha256.Size)
	if h := lastChainTip(dir, filename); h != nil {
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
	rotateBytes, segKeep := auditSegmentConfig()
	a := &auditLog{
		f: f, path: f.Name(), priv: priv, prevHash: prev, domain: domain,
		dir: dir, base: filename, rotateBytes: rotateBytes, segKeep: segKeep, segNext: nextSegNum(dir, filename),
	}
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

// repairTornTail discards an un-acknowledged partial final record (bytes after the last newline,
// left by a power-loss mid-append), so the next append cannot fuse onto the fragment. Byte-identical
// to the collector's. (Cross-cutting audit.)
func repairTornTail(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(b) == 0 || b[len(b)-1] == '\n' {
		return nil
	}
	return os.Truncate(path, int64(bytes.LastIndexByte(b, '\n')+1))
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

// --- ADR-0040: bounded-retention segment rotation -------------------------------------------------
// The signed chains share a fixed 100 MB /data partition; an unbounded append-only log lets one noisy
// tier (egress) fill /data and starve every other chain into a fail-closed append DoS (security-review
// R9). Rotation seals the live file into a numbered segment (<live>.NNNNNN) once it reaches a byte
// threshold, keeps a bounded window of segments, and prunes older ones — capping each chain at
// (segKeep+1)*rotateBytes. The seam is link-continuous (prevHash/seq are NOT reset across a rotation),
// so verifySegmentedChain checks the retained segments + live file as ONE chain. segmentPath/listSegments
// MUST stay byte-identical across src/collector, src/proxy, src/router (the collector's verifier reads the
// segments the proxy/router produce); the "%s.%06d" naming is the shared contract.

// segmentPath is the sealed-segment path for number n: <dir>/<base>.NNNNNN, zero-padded width-6 so the
// lexical order of the names equals their numeric order (6 digits => up to 999999 segments per chain).
func segmentPath(dir, base string, n uint64) string {
	return filepath.Join(dir, fmt.Sprintf("%s.%06d", base, n))
}

// listSegments returns the existing sealed-segment numbers for <dir>/<base>, ascending. A sibling counts
// as a segment IFF its name is exactly base + "." + an all-digit suffix — so the live file, audit-pub.txt,
// a *.tmp, or another chain's files in a shared dir (control.jsonl beside provenance.jsonl) are excluded.
func listSegments(dir, base string) []uint64 {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	prefix := base + "."
	var nums []uint64
	for _, e := range ents {
		if e.IsDir() {
			continue // a sealed segment is always a regular file; never try to verify a directory fd
		}
		name := e.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suf := name[len(prefix):]
		if suf == "" || strings.TrimLeft(suf, "0123456789") != "" {
			continue // not an all-digit suffix
		}
		n, err := strconv.ParseUint(suf, 10, 64)
		if err != nil {
			continue
		}
		nums = append(nums, n)
	}
	sort.Slice(nums, func(i, j int) bool { return nums[i] < nums[j] })
	return nums
}

// nextSegNum returns the number the next sealed segment should get: one past the highest existing segment
// (so a box that rotated, lost power, and rebooted never reuses a number or overwrites signed history), or
// 1 on a chain that has never rotated.
func nextSegNum(dir, base string) uint64 {
	segs := listSegments(dir, base)
	if len(segs) == 0 {
		return 1
	}
	return segs[len(segs)-1] + 1
}

// lastChainTip returns the chain's current tip (last well-formed record hash): the LIVE file's tip, or —
// if the live file is empty/absent (the rename->first-append window after a rotate, or a rotate that
// crashed before its first new record) — the newest non-empty sealed segment's tip, else nil (genesis).
// Used to seed the cross-boot prevHash (F5) and to bind the attest HEADs (ADR-0025) so a quote taken in
// that window binds the newest-segment tip, not a spurious genesis. Per-file tolerance mirrors lastChainHash.
func lastChainTip(dir, base string) []byte {
	if h := lastChainHash(filepath.Join(dir, base)); h != nil {
		return h
	}
	segs := listSegments(dir, base)
	for i := len(segs) - 1; i >= 0; i-- {
		if h := lastChainHash(segmentPath(dir, base, segs[i])); h != nil {
			return h
		}
	}
	return nil
}

// auditSegmentConfig reads the rotation knobs from the environment (ADR-0040). rotateBytes is 0 (rotation
// DISABLED — the pre-R9 single-file behaviour, kept for dev/Buildroot/tests) unless
// BULKHEAD_AUDIT_SEGMENT_BYTES is a positive integer; the appliance *-data.conf drop-ins set it. segKeep is
// the number of sealed segments retained besides the live file (default 1, clamped to a MINIMUM of 1: the
// verifier needs >=1 retained segment as the post-prune on-box anchor, and it keeps the live file always
// linking to a present segment's tip — see verifySegmentedChain). Each chain is bounded at
// (segKeep+1)*rotateBytes on disk (+ <1 record of slack per segment). APPLIANCE BUDGET INVARIANT: Σ over
// the chains of (segKeep+1)*rotateBytes must stay below the /data partition (100 MB) — at 8 MiB / keep=1
// the five chains use 5*(1+1)*8 = 80 MiB.
func auditSegmentConfig() (rotateBytes int64, segKeep int) {
	segKeep = 1
	if v := os.Getenv("BULKHEAD_AUDIT_SEGMENT_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			rotateBytes = n
		}
	}
	if v := os.Getenv("BULKHEAD_AUDIT_SEGMENTS_KEEP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			segKeep = n // a value < 1 is ignored: keep the safe default of 1
		}
	}
	return rotateBytes, segKeep
}

// rotate seals the current live file as the next numbered segment and reopens an empty live file, WITHOUT
// resetting a.prevHash/a.seq — so the first record in the fresh live file links to the sealed segment's tip
// and CONTINUES the seq (the seam is link-continuous; verifySegmentedChain proves it via the existing
// prev_hash check). It then prunes segments older than the retention window. Called from append() under
// a.mu when the live file reaches rotateBytes.
//
// R1 (the critical invariant): rotation must NEVER convert a fill into the fail-closed append DoS R9 exists
// to remove. So rotate() ALWAYS leaves a.f a usable handle: on Sync/Rename failure a.f is the unchanged,
// still-open live file; on a reopen failure after a successful rename it un-renames so the old fd is
// reachable as the live file again. append() treats any returned error as "log and keep writing the current
// file", re-attempting the cap next append. A failed PRUNE is non-fatal (logged).
func (a *auditLog) rotate() error {
	if err := a.f.Sync(); err != nil {
		return err // a.f still open on the live file; append continues on it (R1)
	}
	sealed := segmentPath(a.dir, a.base, a.segNext)
	if err := os.Rename(a.path, sealed); err != nil {
		return err // live file unmoved, a.f still open on it; append continues (R1)
	}
	// The live NAME is now free; the old fd (a.f) still writes the sealed inode. Open a fresh empty live
	// file at a.path and swap to it BEFORE closing the old fd, so a.f is never observed as a closed handle.
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		// Could not create the new live file. Un-rename so a.f's inode is reachable as the live file again (R1).
		if rerr := os.Rename(sealed, a.path); rerr != nil {
			log.Printf("audit: rotate reopen failed AND un-rename failed (%s): %v / %v", a.path, err, rerr)
		}
		return err
	}
	old := a.f
	a.f = f
	a.segNext++
	if cerr := old.Close(); cerr != nil {
		log.Printf("audit: rotate: closing sealed segment %s: %v", sealed, cerr)
	}
	a.pruneSegments()
	return nil
}

// pruneSegments unlinks sealed segments older than the retention window (keeps the newest segKeep). This is
// the step that bounds /data — and the step that moves on-box tamper-detection of the PRUNED records
// off-box (ADR-0040 detection-boundary trade). Best-effort and logged: a failed unlink NEVER fails an
// append (R1); at worst the footprint cap is exceeded transiently and re-attempted on the next rotation.
func (a *auditLog) pruneSegments() {
	segs := listSegments(a.dir, a.base)
	if len(segs) <= a.segKeep {
		return
	}
	for _, n := range segs[:len(segs)-a.segKeep] {
		if err := os.Remove(segmentPath(a.dir, a.base, n)); err != nil {
			log.Printf("audit: prune segment %06d: %v", n, err)
		}
	}
}

// append signs one record and appends it, under the mutex (the router's handlers are concurrent). A single
// write()+Sync() per record (atomic vs a concurrent reader; durable) — the LLM hot path dwarfs the fsync.
//
// TRANSACTIONAL: in-memory chain state (a.seq, a.prevHash) is advanced ONLY after the record is fully on
// stable storage, and a Write/Sync failure truncates the partial/unacked tail back to the pre-append EOF.
// So a single transient I/O error (ENOSPC/EIO) is retried cleanly — it can never leave a durable gapped
// seq or forked prev_hash, either of which would fail-close the verify-audit boot gate on the NEXT boot
// with no self-repair (the seq is per-boot-contiguous and prev_hash chains continuously; see verify.go).
func (a *auditLog) append(ev auditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	nextSeq := a.seq + 1 // a LOCAL: a.seq is not advanced until the write+sync below fully succeed
	r := auditRecord{
		Seq: nextSeq, TS: time.Now().UnixNano(),
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
	// Capture the pre-append EOF so a failed Write/Sync can roll the tail back to it (a.mu makes EOF a
	// stable rollback point — no concurrent appender moves it).
	fi, err := a.f.Stat()
	if err != nil {
		return err
	}
	off := fi.Size()
	// ADR-0040: seal the live file into a segment once it reaches the threshold, BEFORE writing this record
	// (so each record lands whole in one file). The record links to a.prevHash, which rotate() preserves, so
	// it becomes the link-continuous first record of the fresh live file. R1: a rotation error must not fail
	// the append — keep writing the current file and re-attempt the cap next time.
	if a.rotateBytes > 0 && off >= a.rotateBytes {
		if rerr := a.rotate(); rerr != nil {
			log.Printf("audit: segment rotation failed (continuing on current file): %v", rerr)
		} else if nfi, serr := a.f.Stat(); serr == nil {
			off = nfi.Size() // the fresh live file (0 bytes) is the new transactional rollback point
		} else {
			return serr
		}
	}
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

// rollback drops any bytes written past off (the pre-append EOF) so a failed/partial record never strands
// on disk to gap or fork the chain; append() leaves a.seq/a.prevHash uncommitted, so a clean retry
// re-appends from off. Best-effort: a Truncate failure is itself a hard I/O fault and is logged, not fatal.
func (a *auditLog) rollback(off int64) {
	if err := a.f.Truncate(off); err != nil {
		log.Printf("audit: rollback truncate to %d: %v", off, err)
	}
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
// (model + prompt length, and the chosen paid provider for an api route — the provider this request was
// ROUTED to). One signed, non-repudiable record per routing decision.
//
// SEMANTICS (intent, not delivery): this record is written BEFORE the upstream call (record-before-act —
// a failed append refuses the request, so no route ever proceeds un-audited; ADR-0005 fail-closed). So
// provider= attests the routing DECISION, not confirmed delivery: a subsequent upstream 503/timeout/
// missing-key does NOT retract it. This is deliberately conservative — it can over-attribute a paid
// intent that never reached the wire, but it can never HIDE a paid call (which is what a denial-of-wallet
// auditor cares about). A relying party must read provider= as "routed to", not "billed by".
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
