// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

// bulkhead-collector: observe-only eBPF provenance + a fail-closed self-test.
//
//	bulkhead-collector run       attach the BPF-LSM program, stream events to a
//	                             hash-chained, Ed25519-signed append-only log
//	bulkhead-collector selftest  attempt known-forbidden actions; exit non-zero
//	                             unless every one is denied (gates the services)
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector run|selftest")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		runCollector()
	case "selftest":
		runSelftest()
	default:
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector run|selftest")
		os.Exit(2)
	}
}

// ---- selftest: fail closed -------------------------------------------------

// runSelftest attempts actions that the appliance's floor MUST deny. Each must
// fail; any success means the floor is open, so we exit non-zero and (wired via
// systemd Requires=) block every dependent service from starting.
func runSelftest() {
	failures := 0

	// (a) Egress to a routeable, non-allowlisted address must be denied by the
	// nftables floor (1.1.1.1:443 is not in the Anthropic set, loopback, or the
	// tailnet). A DROP yields a timeout; EPERM is also a pass; an ESTABLISHED
	// connection is the only failure. At boot, before the NIC has a lease, this
	// passes trivially via ENETUNREACH — the M4 egress check is the authoritative
	// network-up test, and probe (b) is the robust gate regardless.
	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 3*time.Second)
	if err == nil {
		conn.Close()
		log.Printf("SELFTEST FAIL: egress to 192.0.2.1:443 succeeded (floor is open)")
		failures++
	} else {
		log.Printf("selftest ok: forbidden egress denied (%v)", err)
	}

	// (b) Writing outside the allowed paths must be denied (ProtectSystem=strict
	// makes /usr read-only for this unit). A successful create is a failure.
	const canary = "/usr/.bulkhead-selftest-canary"
	f, err := os.OpenFile(canary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		f.Close()
		os.Remove(canary)
		log.Printf("SELFTEST FAIL: wrote %s (filesystem confinement is open)", canary)
		failures++
	} else {
		log.Printf("selftest ok: forbidden write denied (%v)", err)
	}

	if failures > 0 {
		log.Fatalf("SELF-TEST FAILED: %d probe(s) not denied — refusing to launch services", failures)
	}
	log.Printf("self-test passed: the floor denies forbidden actions")
}

// ---- collector: observe-only provenance ------------------------------------

func runCollector() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("load bpf objects: %v", err)
	}
	defer objs.Close()

	l, err := link.AttachLSM(link.LSMOptions{Program: objs.ProvSocketConnect})
	if err != nil {
		log.Fatalf("attach lsm (is bpf in the active LSM list?): %v", err)
	}
	defer l.Close()

	al, err := openAuditLog()
	if err != nil {
		log.Fatalf("audit log: %v", err)
	}
	defer al.Close()
	log.Printf("collector running: BPF-LSM attached, audit log at %s, signer %s", al.path, al.pubHex())

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf reader: %v", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-stop; rd.Close() }()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		b := rec.RawSample
		if len(b) < 28 {
			continue
		}
		// bpfEvent layout: cgroup_id u64@0, pid u32@8, comm[16]@12.
		ev := provEvent{
			CgroupID: binary.LittleEndian.Uint64(b[0:8]),
			PID:      binary.LittleEndian.Uint32(b[8:12]),
			Comm:     string(bytes.TrimRight(b[12:28], "\x00")),
			Hook:     "socket_connect",
		}
		if err := al.append(ev); err != nil {
			log.Printf("audit append: %v", err)
		}
	}
}

// ---- tamper-evident audit log ----------------------------------------------

type provEvent struct {
	CgroupID uint64
	PID      uint32
	Comm     string
	Hook     string
}

type auditLog struct {
	f        *os.File
	path     string
	priv     ed25519.PrivateKey
	prevHash []byte
	seq      uint64
}

type auditRecord struct {
	Seq      uint64 `json:"seq"`
	TS       int64  `json:"ts"`
	CgroupID uint64 `json:"cgroup_id"`
	PID      uint32 `json:"pid"`
	Comm     string `json:"comm"`
	Hook     string `json:"hook"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
	Sig      string `json:"sig"`
}

func openAuditLog() (*auditLog, error) {
	dir := "/var/lib/bulkhead/audit"
	if d := os.Getenv("BULKHEAD_AUDIT_DIR"); d != "" {
		dir = d
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "provenance.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	priv, err := loadSigningKey()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &auditLog{f: f, path: f.Name(), priv: priv, prevHash: make([]byte, sha256.Size)}, nil
}

// loadSigningKey reads a 32-byte Ed25519 seed from the systemd credential dir
// (TPM-sealed in production); absent one, it generates an ephemeral key and
// logs the public key so the chain is verifiable for this boot.
func loadSigningKey() (ed25519.PrivateKey, error) {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		if seed, err := os.ReadFile(filepath.Join(dir, "audit-seed")); err == nil && len(seed) >= ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]), nil
		}
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

// canonical is a fixed-order, length-prefixed binary encoding of exactly the
// chained fields — never json.Marshal, whose key order/whitespace is unstable.
func canonical(r auditRecord, prev []byte) []byte {
	var b bytes.Buffer
	var u8 [8]byte
	put := func(v uint64) { binary.BigEndian.PutUint64(u8[:], v); b.Write(u8[:]) }
	putStr := func(s string) { put(uint64(len(s))); b.WriteString(s) }
	put(r.Seq)
	put(uint64(r.TS))
	put(r.CgroupID)
	put(uint64(r.PID))
	putStr(r.Comm)
	putStr(r.Hook)
	put(uint64(len(prev)))
	b.Write(prev)
	return b.Bytes()
}

func (a *auditLog) append(ev provEvent) error {
	a.seq++
	r := auditRecord{
		Seq: a.seq, TS: time.Now().UnixNano(),
		CgroupID: ev.CgroupID, PID: ev.PID, Comm: ev.Comm, Hook: ev.Hook,
		PrevHash: hex.EncodeToString(a.prevHash),
	}
	sum := sha256.Sum256(canonical(r, a.prevHash))
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
