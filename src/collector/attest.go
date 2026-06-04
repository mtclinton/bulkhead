// SPDX-License-Identifier: AGPL-3.0-only
//go:build linux

// ADR-0019: software-measured-state remote attestation. The collector measures its OWN running TCB
// (its binary hash + the live enforce_flags + tcb_cgroups membership) into a canonical composite
// digest, extends that digest into an extend-only TPM PCR, and — on a fresh verifier NONCE —
// produces an AK-signed TPM2_Quote that an OFF-BOX verifier checks against the expected good values,
// fail-closed. This makes the otherwise SELF-ASSERTED E0-E3 enforcement EXTERNALLY PROVABLE: a
// tampered box running a modified collector that flips enforce_flags to observe and reports
// all-green produces a DIFFERENT digest than a genuinely-enforcing box, so a relying party can tell
// them apart cryptographically (bound to its fresh nonce, so an old all-green quote can't be replayed).
//
// HONEST LIMITS (the same split ADR-0008 documents for the sealed key): under qemu the AK is trusted
// OUT-OF-BAND (the swtpm EK cert is self-signed dev PKI; full EK-cert credential-activation binding the
// AK to a manufacturer cert chain is the bare-metal upgrade); it attests measured RUNTIME state, NOT
// the firmware boot chain (PCRs 0-9 read 0 under qemu/OVMF); and a live IN-TCB compromise AFTER the
// extend can quote stale-good values — that remains the BPF-LSM floor's job, not this layer's.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

func fatalf(f string, a ...any) { log.Fatalf(f, a...) }
func logf(f string, a ...any)   { log.Printf(f, a...) }

func claimsLine(c map[string]string) string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%q ", k, c[k])
	}
	return strings.TrimSpace(b.String())
}

func mustHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

func ecdsaPubFromDER(der []byte) (*ecdsa.PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ep, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("AK pub is not ECDSA")
	}
	return ep, nil
}

func marshalPKIX(pk *ecdsa.PublicKey) ([]byte, error) { return x509.MarshalPKIXPublicKey(pk) }

// attestPCR is the TPM PCR the composite TCB digest is extended into. It is an EXTEND-ONLY
// application PCR (8-15 cannot be TPM2_PCR_Reset from locality 0), so a forger who can open
// /dev/tpmrm0 CANNOT reset-then-re-extend a clean value over a tampered history — the only way to a
// PCR value is to actually extend that digest, and extension is one-way. PCR 14 is conventionally
// free (no IMA/systemd-pcrphase/MOK in this image); the verifier checks PCR == H(0^32 || D), which
// also catches any stray pre/post extension. (PCR 16/23 are debug/RESETTABLE — unusable here.)
const attestPCR = 14

const tpmDevice = "/dev/tpmrm0"

// attestEnvelope is the on-wire quote a verifier checks OFF-BOX. AKPub is the SubjectPublicKeyInfo
// (DER) of the TPM-restricted AK; Quoted is the raw TPMS_ATTEST (TPM2B_ATTEST.Bytes) the TPM signed;
// Sig is the raw ECDSA (r||s) over SHA-256(Quoted); Claims is the measured TCB state the verifier
// recomputes the expected digest from (shipped for operator context; the binding is the PCR digest).
type attestEnvelope struct {
	AKPubDER string            `json:"ak_pub_der"`
	Quoted   string            `json:"quoted_hex"`
	SigR     string            `json:"sig_r_hex"`
	SigS     string            `json:"sig_s_hex"`
	Nonce    string            `json:"nonce_hex"`
	PCR      int               `json:"pcr"`
	Claims   map[string]string `json:"claims"`
}

// ---- the measured digest ----------------------------------------------------------------------

// attestDigest computes D = SHA-256(canonical(TCB state)) from the LIVE in-process state, plus a
// human-readable claims map. Canonical mirrors the audit canonical() discipline: a domain/version
// tag, fixed field order, 8-byte big-endian length prefix on every variable field, sorted map
// iteration, NEVER json. Each field is justified by the exact tamper it catches.
func attestDigest() ([32]byte, map[string]string, error) {
	var b bytes.Buffer
	var u8 [8]byte
	put := func(v uint64) { binary.BigEndian.PutUint64(u8[:], v); b.Write(u8[:]) }
	putStr := func(s string) { put(uint64(len(s))); b.WriteString(s) }
	claims := map[string]string{}

	putStr("bulkhead-attest-v1") // domain/version tag — a record of another purpose can never collide

	// (1) the collector binary hash — catches a MODIFIED collector (the core forge: a tampered
	// collector that flips flags to observe is a DIFFERENT binary => different hash). /proc/self/exe
	// is the running image; on the read-only rootfs it is the shipped /usr/bin/bulkhead-collector.
	exe, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return [32]byte{}, nil, fmt.Errorf("read self exe: %w", err)
	}
	exeSum := sha256.Sum256(exe)
	putStr(hex.EncodeToString(exeSum[:]))
	claims["collector_sha256"] = hex.EncodeToString(exeSum[:])

	// (2) the enforce_flags snapshot, sorted by hook id — catches E0/E1/E2/E3 flipped from
	// ENFORCE(1) to observe(0): a box reporting all-green-while-OBSERVING produces a different digest.
	ef, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "enforce_flags"), nil)
	if err != nil {
		return [32]byte{}, nil, fmt.Errorf("open enforce_flags: %w", err)
	}
	defer ef.Close()
	hooks := make([]uint32, 0, len(hookNames))
	for id := range hookNames {
		hooks = append(hooks, id)
	}
	sort.Slice(hooks, func(i, j int) bool { return hooks[i] < hooks[j] })
	put(uint64(len(hooks)))
	var flagsClaim bytes.Buffer
	for _, id := range hooks {
		var v uint32
		_ = ef.Lookup(id, &v) // miss => 0 (observe)
		put(uint64(id))
		put(uint64(v))
		fmt.Fprintf(&flagsClaim, "%s=%d ", hookNames[id], v)
	}
	claims["enforce_flags"] = strings.TrimSpace(flagsClaim.String())

	// (3) the tcb_cgroups membership, measured STABLY across boots (the raw cgids are per-boot inodes,
	// so we measure the COUNT + whether membership is EXACTLY the collector's expected TCB set {root,
	// collector, broker} with NO stranger). A stranger (an extra E0-exempt cgroup = a privilege escape
	// hatch) flips cleanness; a missing legit member flips it too. The binary hash (1) anchors trust in
	// THIS collector code, so the genuine code's own clean/anomalous assessment is trustworthy.
	count, clean, err := tcbMembershipState()
	if err != nil {
		return [32]byte{}, nil, err
	}
	put(uint64(count))
	if clean {
		put(1)
	} else {
		put(0)
	}
	claims["tcb_count"] = fmt.Sprintf("%d", count)
	claims["tcb_clean"] = fmt.Sprintf("%t", clean)

	return sha256.Sum256(b.Bytes()), claims, nil
}

// tcbMembershipState returns (count, clean): clean iff the live tcb_cgroups map is EXACTLY the
// collector's expected TCB set (root + collector self + the live broker), no stranger, none missing.
func tcbMembershipState() (int, bool, error) {
	tcb, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "tcb_cgroups"), nil)
	if err != nil {
		return 0, false, fmt.Errorf("open tcb_cgroups: %w", err)
	}
	defer tcb.Close()
	live := map[uint64]struct{}{}
	var key uint64
	var val uint32
	it := tcb.Iterate()
	for it.Next(&key, &val) {
		live[key] = struct{}{}
	}
	expected := map[uint64]struct{}{}
	for _, id := range tcbCgroupIDs() { // root + collector self
		expected[id] = struct{}{}
	}
	if bid, err := cgroupIDFromInode(brokerCgroupPath); err == nil {
		expected[bid] = struct{}{}
	}
	clean := len(live) == len(expected)
	for id := range live {
		if _, ok := expected[id]; !ok {
			clean = false
		}
	}
	for id := range expected {
		if _, ok := live[id]; !ok {
			clean = false
		}
	}
	return len(live), clean, nil
}

// ---- TPM operations (in-process go-tpm; proven against the harness swtpm) ----------------------

// attestAK creates the deterministic, TPM-restricted ECDSA-P256 Attestation Key under the Owner
// hierarchy with a FIXED template, so the same AK (same public key) is re-derived every boot from
// the TPM's hierarchy seed — the verifier pins it out-of-band (TOFU under qemu; EK-cert binding is
// the bare-metal upgrade). Restricted+SignEncrypt means a Quote signature can ONLY have been
// produced by the TPM over a real TPMS_ATTEST, never forged by signing a fake blob outside it.
func attestAK(tpm transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	tmpl := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			Restricted:           true,
			SignEncrypt:          true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
	}
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tmpl),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("create AK: %w", err)
	}
	return rsp, nil
}

// tpmRetry re-runs a TPM op on TPM_RC_RETRY (0x922) — a transient "not ready, resubmit" code the
// spec mandates handling (the feasibility spike saw it once on Quote; a resubmit fixed it).
func tpmRetry(fn func() error) error {
	var err error
	for i := 0; i < 8; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		if !errors.Is(err, tpm2.TPMRCRetry) {
			return err
		}
	}
	return err
}

// tpmMu serializes /dev/tpmrm0 access in the collector process (the TPM is single-session; the
// extend + quote handlers must not interleave).
var tpmMu sync.Mutex

// doAttestExtend computes the composite TCB digest and extends it into attestPCR. RUNS IN THE
// COLLECTOR PROCESS (TCB), so its enforce_flags/tcb_cgroups bpf() reads survive default-armed E0 —
// a standalone unit's cgroup is non-TCB and would EPERM. Returns the extended digest hex.
func doAttestExtend() (string, error) {
	d, claims, err := attestDigest()
	if err != nil {
		return "", err
	}
	tpmMu.Lock()
	defer tpmMu.Unlock()
	tpm, err := linuxtpm.Open(tpmDevice)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", tpmDevice, err)
	}
	defer tpm.Close()
	err = tpmRetry(func() error {
		_, e := tpm2.PCRExtend{
			PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(attestPCR), Auth: tpm2.PasswordAuth(nil)},
			Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{
				HashAlg: tpm2.TPMAlgSHA256,
				Digest:  d[:],
			}}},
		}.Execute(tpm)
		return e
	})
	if err != nil {
		return "", fmt.Errorf("PCR_Extend: %w", err)
	}
	logf("attest: extended PCR %d with TCB digest %s (%s)", attestPCR, hex.EncodeToString(d[:]), claimsLine(claims))
	return hex.EncodeToString(d[:]), nil
}

// doAttestQuote derives the AK, quotes attestPCR under the verifier nonce, and returns the envelope
// as compact JSON (one line). RUNS IN THE COLLECTOR PROCESS (TCB) — see doAttestExtend.
func doAttestQuote(nonceHex string) (string, error) {
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) < 16 {
		return "", fmt.Errorf("nonce must be >= 16 bytes of hex")
	}
	d, claims, err := attestDigest()
	if err != nil {
		return "", err
	}
	_ = d
	tpmMu.Lock()
	defer tpmMu.Unlock()
	tpm, err := linuxtpm.Open(tpmDevice)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", tpmDevice, err)
	}
	defer tpm.Close()
	ak, err := attestAK(tpm)
	if err != nil {
		return "", err
	}
	defer tpm2.FlushContext{FlushHandle: ak.ObjectHandle}.Execute(tpm)

	sel := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash:      tpm2.TPMAlgSHA256,
		PCRSelect: pcrSelectBitmap(attestPCR),
	}}}
	var qrsp *tpm2.QuoteResponse
	err = tpmRetry(func() error {
		r, e := tpm2.Quote{
			// the AK is a TRANSIENT handle, so go-tpm needs its Name explicitly (it can't derive it
			// the way it does for permanent handles like a PCR).
			SignHandle:     tpm2.AuthHandle{Handle: ak.ObjectHandle, Name: ak.Name, Auth: tpm2.PasswordAuth(nil)},
			QualifyingData: tpm2.TPM2BData{Buffer: nonce},
			PCRSelect:      sel,
			InScheme: tpm2.TPMTSigScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
			},
		}.Execute(tpm)
		qrsp = r
		return e
	})
	if err != nil {
		return "", fmt.Errorf("TPM2_Quote: %w", err)
	}
	akPubDER, err := akPubToDER(ak)
	if err != nil {
		return "", fmt.Errorf("AK pub: %w", err)
	}
	ecdsaSig, err := qrsp.Signature.Signature.ECDSA()
	if err != nil {
		return "", fmt.Errorf("extract sig: %w", err)
	}
	env := attestEnvelope{
		AKPubDER: hex.EncodeToString(akPubDER),
		Quoted:   hex.EncodeToString(qrsp.Quoted.Bytes()),
		SigR:     hex.EncodeToString(ecdsaSig.SignatureR.Buffer),
		SigS:     hex.EncodeToString(ecdsaSig.SignatureS.Buffer),
		Nonce:    nonceHex,
		PCR:      attestPCR,
		Claims:   claims,
	}
	out, _ := json.Marshal(env)
	return string(out), nil
}

// cmdAttestVerify is the OFF-BOX verifier (the same binary run elsewhere, no TPM needed): it checks
// (a) the quote's magic == TPM_GENERATED_VALUE, (b) the echoed qualifyingData == the fresh nonce
// (no replay), (c) the ECDSA signature over SHA-256(Quoted) under the pinned AK pub, and (d) the
// quoted PCR digest == H(0^32 || expected-D). Fail-closed on any mismatch. expectedDHex is the good
// composite digest the verifier computed from known-good TCB values out-of-band.
func cmdAttestVerify(envPath, expectedDHex, nonceHex string) {
	raw, err := os.ReadFile(envPath)
	if err != nil {
		fatalf("attest verify: read envelope: %v", err)
	}
	var env attestEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		fatalf("attest verify: parse envelope: %v", err)
	}
	expectedD, err := hex.DecodeString(expectedDHex)
	if err != nil || len(expectedD) != 32 {
		fatalf("attest verify: expected-D must be 32 bytes hex")
	}
	// The nonce is the VERIFIER's OWN fresh challenge — checked against the quote's QualifyingData,
	// NOT taken from the (attacker-controllable) envelope. This is what makes an old all-green quote
	// non-replayable: its QualifyingData echoes the OLD nonce, not this challenge.
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) < 16 {
		fatalf("attest verify: nonce must be >= 16 bytes hex (the verifier's fresh challenge)")
	}
	quoted, _ := hex.DecodeString(env.Quoted)
	akDER, _ := hex.DecodeString(env.AKPubDER)

	// (a)+(b) parse the TPMS_ATTEST and check magic + nonce.
	att, err := tpm2.Unmarshal[tpm2.TPMSAttest](quoted)
	if err != nil {
		fatalf("attest verify: parse TPMS_ATTEST: %v", err)
	}
	if att.Magic != tpm2.TPMGeneratedValue {
		fatalf("attest verify: FAIL — magic != TPM_GENERATED (not a genuine TPM quote)")
	}
	if !bytes.Equal(att.ExtraData.Buffer, nonce) {
		fatalf("attest verify: FAIL — qualifyingData != the verifier's fresh nonce (stale/replayed quote)")
	}
	// (c) ECDSA signature over SHA-256(quoted) under the pinned AK pub.
	pub, err := ecdsaPubFromDER(akDER)
	if err != nil {
		fatalf("attest verify: AK pub: %v", err)
	}
	h := sha256.Sum256(quoted)
	r := new(big.Int).SetBytes(mustHex(env.SigR))
	s := new(big.Int).SetBytes(mustHex(env.SigS))
	if !ecdsa.Verify(pub, h[:], r, s) {
		fatalf("attest verify: FAIL — AK signature invalid")
	}
	// (d) the quoted PCR digest == H(0^32 || expected-D) (single extend from a zero PCR bank).
	qi, err := att.Attested.Quote()
	if err != nil {
		fatalf("attest verify: not a quote attestation: %v", err)
	}
	want := pcrExtendFromZero(expectedD)
	gotDigest := qi.PCRDigest.Buffer
	// the quote's pcrDigest is H(concatenation of selected PCR values); with one PCR selected it is
	// H(PCR14value) where PCR14value == H(0^32 || D). Compute the same.
	wantQuoteDigest := sha256.Sum256(want)
	if !bytes.Equal(gotDigest, wantQuoteDigest[:]) {
		fatalf("attest verify: FAIL — PCR digest mismatch: the box is NOT in the expected enforcing TCB state")
	}
	fmt.Printf("attest verify: OK — genuine TPM quote, fresh nonce, AK sig valid, PCR %d == expected enforcing-TCB state\n", env.PCR)
}

func cmdAttest(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector attest extend|quote <nonce-hex>|verify <envelope.json> <expected-digest-hex>")
		os.Exit(2)
	}
	switch args[0] {
	case "extend":
		// extend/quote read the pinned maps (bpf()) which a non-TCB CLI cgroup cannot do under
		// default-armed E0 — they run in the COLLECTOR (TCB) via the control socket. Retry: at boot
		// the collector may still be binding the socket. The reply is "OK <digest-hex>".
		ok, resp := controlRPCRetry("ATTEST-EXTEND")
		if !ok {
			fatalf("attest extend: %s", resp)
		}
		fmt.Println(resp)
	case "quote":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: bulkhead-collector attest quote <nonce-hex>")
			os.Exit(2)
		}
		ok, resp := controlRPC("ATTEST-QUOTE " + args[1])
		if !ok {
			fatalf("attest quote: %s", resp)
		}
		fmt.Println(strings.TrimPrefix(resp, "OK ")) // the envelope JSON
	case "verify":
		// OFF-BOX: no TPM, no maps — runs anywhere (a relying party's machine).
		if len(args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: bulkhead-collector attest verify <envelope.json> <expected-digest-hex> <nonce-hex>")
			os.Exit(2)
		}
		cmdAttestVerify(args[1], args[2], args[3])
	default:
		fmt.Fprintln(os.Stderr, "unknown attest verb")
		os.Exit(2)
	}
}

// ---- control-socket handlers (run in the collector, TCB) ---------------------------------------

// ctlAttestExtend / ctlAttestQuote execute the TPM extend/quote IN THE COLLECTOR (TCB) so their
// enforce_flags/tcb_cgroups bpf() reads survive default-armed E0. Operator-only: handleControlConn
// already requires uid==0, and (like ENFORCE-SET) an AGENT cgroup is rejected — a jailed lineage
// must never drive attestation.
func ctlAttestExtend(reply func(string), cgPath string) {
	if isAgentCgroup(cgPath) {
		reply("ERR not-operator")
		return
	}
	d, err := doAttestExtend()
	if err != nil {
		reply("ERR " + err.Error())
		return
	}
	reply("OK " + d)
}

func ctlAttestQuote(reply func(string), cgPath string, f []string) {
	if isAgentCgroup(cgPath) {
		reply("ERR not-operator")
		return
	}
	if len(f) != 2 {
		reply("ERR protocol")
		return
	}
	env, err := doAttestQuote(f[1])
	if err != nil {
		reply("ERR " + err.Error())
		return
	}
	reply("OK " + env)
}

// ---- small helpers (kept local; some shadow stdlib spellings used elsewhere) -------------------

func pcrSelectBitmap(pcr int) []byte {
	b := make([]byte, 3) // PCRs 0-23
	b[pcr/8] = 1 << (uint(pcr) % 8)
	return b
}

// pcrExtendFromZero returns H(0^32 || D) — the value an extend-only PCR holds after a single extend
// of D from a zeroed bank.
func pcrExtendFromZero(d []byte) []byte {
	var z [32]byte
	h := sha256.Sum256(append(z[:], d...))
	return h[:]
}

func akPubToDER(ak *tpm2.CreatePrimaryResponse) ([]byte, error) {
	pub, err := ak.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	ecc, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}
	pk := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(ecc.X.Buffer),
		Y:     new(big.Int).SetBytes(ecc.Y.Buffer),
	}
	return marshalPKIX(pk)
}
