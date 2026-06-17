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
	"sort"
	"strconv"
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
	// ADR-0038 segment rotation (all guarded by a.mu, set once in openAuditLog except segNext, bumped by
	// rotate()). dir/base locate the chain; rotateBytes>0 enables rotation; segKeep is the retained window.
	dir         string
	base        string
	rotateBytes int64
	segKeep     int
	segNext     uint64
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
	// Discard an un-acked partial final record (a power-loss can leave append's "line\n" without its
	// '\n'); else O_APPEND fuses the next record onto the fragment, false-bricking verify-audit two
	// boots later. Best-effort. (Cross-cutting audit 2026-06-16; mirrors the collector's repair.)
	if err := repairTornTail(chainPath); err != nil {
		logd("AUDIT-REPAIR", chainPath, "", err.Error())
	}
	// Seed the cross-boot prevHash (F5) from the chain TIP, which after a rotation lives in the live file
	// OR — in the rename->first-append window — the newest sealed segment (lastChainTip, ADR-0038), never a
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

// repairTornTail discards an un-acknowledged partial final record (bytes after the last newline,
// left by a power-loss mid-append), restoring "a sequence of newline-terminated records" so the next
// append cannot fuse onto the fragment. Byte-identical to the collector's. (Cross-cutting audit.)
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

// --- ADR-0038: bounded-retention segment rotation -------------------------------------------------
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

// auditSegmentConfig reads the rotation knobs from the environment (ADR-0038). rotateBytes is 0 (rotation
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
// off-box (ADR-0038 detection-boundary trade). Best-effort and logged: a failed unlink NEVER fails an
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
	// ADR-0038: seal the live file into a segment once it reaches the threshold, BEFORE writing this record
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

// boundMode caps a Mode string to keep the signed chain bounded — inc2 records can carry a request
// path or a deny rule name that is longer than a bare dst. Rune-safe truncation (same as recordEgress).
func boundMode(s string) string {
	if len(s) <= maxAuditDstLen {
		return s
	}
	cut := maxAuditDstLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "...(truncated)"
}

// recordPassthrough (ADR-0034 inc2) signs an explicit "this allowed flow was NOT body-inspected"
// record (Hook="passthrough") so the chain honestly accounts for every uninspected channel — the
// ADR-0093 open-question requirement, made measurable: counting Hook=inspect vs Hook=passthrough
// records is exactly the fraction of egress that was body-inspected. reason is "default" (mode
// passthrough) or "pinned" (cert-pinned/mTLS, where MITM would break the flow by construction).
func (a *auditLog) recordPassthrough(host, port, reason string) error {
	dst := host
	if port != "" {
		dst = host + ":" + port
	}
	return a.append(auditEvent{Comm: "egress-proxy", Hook: "passthrough", Decision: "allow",
		Mode: boundMode("dst=" + dst + " reason=" + reason)})
}

// recordInspect (ADR-0034 inc2) signs one CONTENT decision for a TLS-terminated flow
// (Hook="inspect"). It records method/host/path/sizes/verdict — NEVER the body, so the chain stays
// bounded and no secret material is ever written to disk; a deny carries only the triggering rule
// name as reason. Same record-before-act / fail-closed discipline as recordEgress (the caller drops
// the flow on a failed append).
func (a *auditLog) recordInspect(host, method, path string, reqBytes, respBytes int64, decision, reason string) error {
	mode := fmt.Sprintf("host=%s method=%s path=%s reqb=%d respb=%d", host, method, path, reqBytes, respBytes)
	if reason != "" {
		mode += " reason=" + reason
	}
	return a.append(auditEvent{Comm: "egress-proxy", Hook: "inspect", Decision: decision, Mode: boundMode(mode)})
}
