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
// HONEST LIMITS (the same split ADR-0008 documents for the sealed key): the verifier PINS the AK
// out-of-band (captured via `attest akpub`) and now ROOTS that pin in the TPM via EK-cert credential-
// activation (ADR-0020 — `attest ek`/`make-credential`/`activate`/`enroll-verify`): the recovered
// secret returns ONLY from the genuine TPM owning the EK that also holds the wrapped AK Name, so the
// pin is bound to THIS box's TPM, not merely "a TPM". What stays bare-metal is chaining the EK cert to
// a MANUFACTURER CA root — swtpm's EK cert is self-signed dev PKI, so under qemu the EK-binding
// MECHANISM is proven but silicon-genuineness is not (the verifier supplies the vendor EK-CA on bare
// metal; the same code path then validates the chain + asserts cert-pub == EK-pub). D attests the
// enforce POSTURE (which hooks are armed) + the collector binary + TCB cleanliness, NOT per-agent
// egress-manifest / one-shot-grant CONTENTS (runtime state written per-agent AFTER this boot extend,
// so out of this stable snapshot by design). It attests measured RUNTIME state, NOT the firmware boot
// chain (PCRs 0-9 read 0 under qemu/OVMF); and a live IN-TCB compromise AFTER the extend can quote
// stale-good values — those remain the BPF-LSM floor's continuous job, not this layer's.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// ---- EK-cert credential-activation (ADR-0020): ROOT the AK in the TPM EK ------------------------
//
// The AK pin (ADR-0019) is blind TOFU — it proves the quote came from SOME TPM holding that AK, not
// that the AK belongs to THE expected box's genuine TPM. Credential-activation closes that: the box
// exports its EK pub (+ EK cert) and AK pub/Name; an OFF-BOX verifier validates the EK cert (bare
// metal: chain to a manufacturer EK-CA + cert-pub == EK-pub) and runs MakeCredential(EKpub, secret,
// AKName) → a challenge ONLY the genuine TPM owning that EK, also holding the AK of that Name, can
// decrypt; the box ActivateCredentials it and returns the secret. A match means the AK is provably
// loaded in the same TPM that owns the EK — so the verifier pins a now-EK-ROOTED AK. The AK template
// is UNCHANGED (binding is by Name, hierarchy-independent), so the enrolled pin is byte-identical to
// the quote AK and the ADR-0019 verify/harness are regression-free.

// enrollRequest is the box's enrollment request (from ATTEST-EK). EKPubTPMT is the marshaled
// TPMT_PUBLIC (fed straight to ImportEncapsulationKey); EKCertDER is the X.509 EK cert (best-effort,
// "" if absent); AKPubDER is the PKIX pin-to-be (== the ADR-0019 pin); AKPubTPMT is the marshaled AK
// TPMT_PUBLIC (so the verifier independently recomputes the Name + PKIX); AKName is the box's CLAIMED
// Name, which the verifier RECOMPUTES from AKPubTPMT and never trusts.
type enrollRequest struct {
	EKPubTPMT string `json:"ek_pub_tpmt"`
	EKCertDER string `json:"ek_cert_der"`
	EKNVIndex string `json:"ek_nv_index"`
	AKPubDER  string `json:"ak_pub_der"`
	AKPubTPMT string `json:"ak_pub_tpmt"`
	AKName    string `json:"ak_name"`
}

// activationChallenge is the verifier's MakeCredential output (from make-credential): a fresh secret
// encapsulated to the EK and bound to the AK Name.
type activationChallenge struct {
	CredBlob  string `json:"cred_blob"`
	EncSecret string `json:"enc_secret"`
}

// activationResponse is the box's recovered secret (from ATTEST-ACTIVATE).
type activationResponse struct {
	RecoveredSecret string `json:"recovered_secret"`
}

// verifierRound is make-credential's PRIVATE per-round state (NOT on the wire): the fresh secret it
// wrapped AND the RECOMPUTED PKIX of the key it bound that secret to (== the AK whose Name the secret
// was wrapped to). enroll-verify consumes ONLY this — so the pinned key is provably the one the
// recovered secret proves possession of, with no re-suppliable enrollRequest in the trust path (a
// separately-supplied request could otherwise pin key A while the secret only proved possession of B).
type verifierRound struct {
	Secret   string `json:"secret"`
	AKPubDER string `json:"ak_pub_der"`
}

// ---- the measured digest ----------------------------------------------------------------------

// composeDigest is the PURE canonical serialization shared by the LIVE attestDigest AND the OFF-BOX
// `attest expected-D` subcommand (ADR-0022) — ONE source of truth, so the box's extended digest and a
// relying party's independently-computed expected digest are byte-identical. THAT is what breaks the
// journal-circularity: the verifier derives the expected D from the known-good (byte-reproducible)
// collector binary + the expected posture, never from the box's own `attest: extended` journal line.
// Canonical = domain/version tag, fixed field order, 8-byte BE length prefix on every variable field,
// hook ids sorted ascending, NEVER json (mirrors the audit canonical() discipline). Any change to
// these bytes is a digest FORMAT change and MUST bump the domain tag; TestComposeDigestGoldenV1 pins
// the v1 bytes (and TestComposeDigestFieldsBind / TestComposeDigestAbsentHookIsObserve the semantics)
// so a silent drift fails CI.
func composeDigest(exeHashHex string, flagVals map[uint32]uint32, tcbCount int, tcbClean bool) [32]byte {
	var b bytes.Buffer
	var u8 [8]byte
	put := func(v uint64) { binary.BigEndian.PutUint64(u8[:], v); b.Write(u8[:]) }
	putStr := func(s string) { put(uint64(len(s))); b.WriteString(s) }

	putStr("bulkhead-attest-v1") // (0) domain/version tag — a record of another purpose can never collide
	putStr(exeHashHex)           // (1) collector binary hash — catches a MODIFIED collector
	// (2) the enforce_flags snapshot over the canonical hook set (hookNames keys), sorted ascending so
	// both callers serialize the SAME set/order; absent => 0 (observe), mirroring the live Lookup miss.
	hooks := sortedHookIDs()
	put(uint64(len(hooks)))
	for _, id := range hooks {
		put(uint64(id))
		put(uint64(flagVals[id]))
	}
	// (3) the tcb_cgroups membership state (count, clean) — catches a stranger or a missing member.
	put(uint64(tcbCount))
	if tcbClean {
		put(1)
	} else {
		put(0)
	}
	return sha256.Sum256(b.Bytes())
}

// sortedHookIDs is the canonical hook-id set (hookNames keys) ascending — the single ordering both
// the digest serialization and the live flag read iterate.
func sortedHookIDs() []uint32 {
	hooks := make([]uint32, 0, len(hookNames))
	for id := range hookNames {
		hooks = append(hooks, id)
	}
	sort.Slice(hooks, func(i, j int) bool { return hooks[i] < hooks[j] })
	return hooks
}

// expectedTCBCount is the size of the genuine TCB set {root, collector, broker} — the count a relying
// party expects, and what tcbMembershipState measures live on a clean hardened boot.
const expectedTCBCount = 3

// attestDigest computes D = composeDigest(LIVE in-process state), plus a human-readable claims map.
// The collector binary hash catches a MODIFIED collector; the enforce_flags snapshot catches a hook
// flipped to observe (POSTURE, not per-agent policy CONTENTS — egress_policy/grant_once are runtime);
// the tcb (count, clean) catches a TCB stranger or missing member.
func attestDigest() ([32]byte, map[string]string, error) {
	claims := map[string]string{}

	exe, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return [32]byte{}, nil, fmt.Errorf("read self exe: %w", err)
	}
	exeSum := sha256.Sum256(exe)
	exeHex := hex.EncodeToString(exeSum[:])
	claims["collector_sha256"] = exeHex

	ef, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "enforce_flags"), nil)
	if err != nil {
		return [32]byte{}, nil, fmt.Errorf("open enforce_flags: %w", err)
	}
	defer ef.Close()
	flagVals := map[uint32]uint32{}
	var flagsClaim bytes.Buffer
	for _, id := range sortedHookIDs() {
		var v uint32
		_ = ef.Lookup(id, &v) // miss => 0 (observe)
		flagVals[id] = v
		fmt.Fprintf(&flagsClaim, "%s=%d ", hookNames[id], v)
	}
	claims["enforce_flags"] = strings.TrimSpace(flagsClaim.String())

	count, clean, err := tcbMembershipState()
	if err != nil {
		return [32]byte{}, nil, err
	}
	claims["tcb_count"] = fmt.Sprintf("%d", count)
	claims["tcb_clean"] = fmt.Sprintf("%t", clean)

	return composeDigest(exeHex, flagVals, count, clean), claims, nil
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

// ---- posture gate (ADR-0021): make attestation LOAD-BEARING ------------------------------------

// gatePosture reports whether the box is in the expected ENFORCING posture: E0 (bpf) armed AND E2
// (socket_connect) armed AND tcb_cgroups clean — read LIVE from the SAME pinned maps attestDigest
// reads (ONE source of truth, no new map-read code). Miss => 0 => observe (mirrors attestDigest), so
// an empty / RemoveAll-reset enforce_flags reads as NOT armed and FAILS CLOSED; a map-OPEN error is
// returned (=> the CLI exits non-zero => fail-closed), never silently "assume armed". It requires
// EXACTLY the ADR-0018 default-armed set {E0,E2}: requiring E1/E3 (never armed by default) would fail
// every healthy hardened boot, and requiring less would let an E2-dropped-to-observe box (egress floor
// down) still pass. A stranger in tcb_cgroups is an E0-EXEMPT escape hatch, so "armed but dirty TCB"
// must NOT pass. This is a SELF-ASSERTED on-box predicate (a tampered collector defeats it), NOT a
// TPM-quoted off-box proof — the EK-rooted-quote self-verify is the explicit follow-up.
func gatePosture() (bool, string, error) {
	ef, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "enforce_flags"), nil)
	if err != nil {
		return false, "", fmt.Errorf("open enforce_flags: %w", err)
	}
	defer ef.Close()
	armed := func(h uint32) bool { var v uint32; _ = ef.Lookup(h, &v); return v == 1 } // miss => 0 => observe
	e0, e2 := armed(hookBPF), armed(hookConnect)
	count, clean, err := tcbMembershipState()
	if err != nil {
		return false, "", err
	}
	detail := fmt.Sprintf("e0=%d e2=%d tcb_clean=%t count=%d", b2i(e0), b2i(e2), clean, count)
	return e0 && e2 && clean, detail, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
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

// doAttestEK builds the enrollment request: the transient EK (ECC-P256 restricted-decrypt under the
// Endorsement hierarchy, TCG template), the SAME owner AK the quote uses (so the enrolled identity IS
// the quote identity), and a best-effort read of the X.509 EK cert. RUNS IN THE COLLECTOR (TCB).
func doAttestEK() (string, error) {
	tpmMu.Lock()
	defer tpmMu.Unlock()
	tpm, err := linuxtpm.Open(tpmDevice)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", tpmDevice, err)
	}
	defer tpm.Close()
	ekRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}.Execute(tpm)
	if err != nil {
		return "", fmt.Errorf("create EK: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: ekRsp.ObjectHandle}.Execute(tpm)
	ekPub, err := ekRsp.OutPublic.Contents()
	if err != nil {
		return "", fmt.Errorf("EK pub: %w", err)
	}
	ak, err := attestAK(tpm)
	if err != nil {
		return "", err
	}
	defer tpm2.FlushContext{FlushHandle: ak.ObjectHandle}.Execute(tpm)
	akPub, err := ak.OutPublic.Contents()
	if err != nil {
		return "", fmt.Errorf("AK pub: %w", err)
	}
	akPubDER, err := akPubToDER(ak)
	if err != nil {
		return "", fmt.Errorf("AK PKIX: %w", err)
	}
	certDER, nvIdx := readEKCert(tpm) // best-effort: ("", "") on any miss
	req := enrollRequest{
		EKPubTPMT: hex.EncodeToString(tpm2.Marshal(*ekPub)),
		EKCertDER: hex.EncodeToString(certDER),
		EKNVIndex: nvIdx,
		AKPubDER:  hex.EncodeToString(akPubDER),
		AKPubTPMT: hex.EncodeToString(tpm2.Marshal(*akPub)),
		AKName:    hex.EncodeToString(ak.Name.Buffer),
	}
	out, _ := json.Marshal(req)
	logf("attest: EK enrollment request (ek_nv_index=%q ek_cert=%dB ak_name=%s)",
		nvIdx, len(certDER), hex.EncodeToString(ak.Name.Buffer))
	return string(out), nil
}

// ekCandidateIndices are the NV indices an EK cert may live at: ECC spec-canonical, an swtpm alt, and
// RSA. Probed in order; first that reads + X.509-parses wins.
func ekCandidateIndices() []uint32 { return []uint32{0x01c0000a, 0x01c00016, 0x01c00002} }

// readEKCert best-effort reads the X.509 EK cert from NV. Returns ("", "") on any miss — the
// enrollment still proves EK-binding from the EK pub alone (the cert is the bare-metal trust anchor).
func readEKCert(tpm transport.TPM) ([]byte, string) {
	for _, idx := range ekCandidateIndices() {
		rp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(idx)}.Execute(tpm)
		if err != nil {
			continue
		}
		nvpub, err := rp.NVPublic.Contents()
		if err != nil {
			continue
		}
		size := uint32(nvpub.DataSize)
		if size == 0 || size > 8192 {
			continue
		}
		buf := make([]byte, 0, size)
		var off uint32
		ok := true
		for off < size {
			chunk := size - off
			if chunk > 512 {
				chunk = 512
			}
			rd, err := tpm2.NVRead{
				AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(idx), Name: rp.NVName, Auth: tpm2.PasswordAuth(nil)},
				NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(idx), Name: rp.NVName},
				Size:       uint16(chunk),
				Offset:     uint16(off),
			}.Execute(tpm)
			if err != nil {
				ok = false
				break
			}
			buf = append(buf, rd.Data.Buffer...)
			off += chunk
		}
		if !ok {
			continue
		}
		if _, err := x509.ParseCertificate(buf); err != nil {
			continue // not a parseable cert at this index
		}
		return buf, fmt.Sprintf("0x%08x", idx)
	}
	return nil, ""
}

// doAttestActivate recovers the credential-activation secret: re-derive the EK + AK, satisfy the EK's
// AuthPolicy (TPM2_PolicySecret(RH_ENDORSEMENT)) in a fresh policy session, then ActivateCredential.
// The recovered secret returns ONLY from the genuine TPM owning this EK AND holding the wrapped AK
// Name — so returning it (and the verifier matching it to its fresh challenge) is the EK-rooting proof.
func doAttestActivate(credBlobHex, encSecretHex string) (string, error) {
	credBlob, err := hex.DecodeString(credBlobHex)
	if err != nil {
		return "", fmt.Errorf("cred_blob hex: %w", err)
	}
	encSecret, err := hex.DecodeString(encSecretHex)
	if err != nil {
		return "", fmt.Errorf("enc_secret hex: %w", err)
	}
	tpmMu.Lock()
	defer tpmMu.Unlock()
	tpm, err := linuxtpm.Open(tpmDevice)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", tpmDevice, err)
	}
	defer tpm.Close()
	ekRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
	}.Execute(tpm)
	if err != nil {
		return "", fmt.Errorf("create EK: %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: ekRsp.ObjectHandle}.Execute(tpm)
	ak, err := attestAK(tpm)
	if err != nil {
		return "", err
	}
	defer tpm2.FlushContext{FlushHandle: ak.ObjectHandle}.Execute(tpm)

	var recovered []byte
	err = tpmRetry(func() error {
		// the EK is UserWithAuth:false + AdminWithPolicy:true with AuthPolicy == PolicySecret(endorsement);
		// build a FRESH policy session each attempt (a consumed session can't be reused) and satisfy it
		// before ActivateCredential uses the EK as KeyHandle.
		sess, closeSess, e := tpm2.PolicySession(tpm, tpm2.TPMAlgSHA256, 16)
		if e != nil {
			return e
		}
		defer closeSess()
		if _, e = (tpm2.PolicySecret{
			AuthHandle:    tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(nil)},
			PolicySession: sess.Handle(),
			NonceTPM:      sess.NonceTPM(),
		}).Execute(tpm); e != nil {
			return e
		}
		ac, e := tpm2.ActivateCredential{
			ActivateHandle: tpm2.AuthHandle{Handle: ak.ObjectHandle, Name: ak.Name, Auth: tpm2.PasswordAuth(nil)},
			KeyHandle:      tpm2.AuthHandle{Handle: ekRsp.ObjectHandle, Name: ekRsp.Name, Auth: sess},
			CredentialBlob: tpm2.TPM2BIDObject{Buffer: credBlob},
			Secret:         tpm2.TPM2BEncryptedSecret{Buffer: encSecret},
		}.Execute(tpm)
		if e != nil {
			return e
		}
		recovered = ac.CertInfo.Buffer
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("ActivateCredential: %w", err)
	}
	resp := activationResponse{RecoveredSecret: hex.EncodeToString(recovered)}
	out, _ := json.Marshal(resp)
	return string(out), nil
}

// cmdAttestVerify is the OFF-BOX verifier (the same binary run elsewhere, no TPM needed). It PINS the
// AK out-of-band — pinnedAK is the expected box's AK pub (PKIX DER hex, or @file), captured on a
// trusted first contact (TOFU) via `attest akpub` — and REJECTS any envelope whose AK differs, BEFORE
// trusting it to verify the signature. Without this pin the verifying key would be read straight from
// the (attacker-controllable) envelope, and ANY genuine TPM (or even a hand-rolled software key over a
// fabricated TPMS_ATTEST) could forge a PASS for the expected box. It then checks (a) the quote's
// magic == TPM_GENERATED_VALUE, (b) the echoed qualifyingData == the fresh nonce (no replay), (c) the
// ECDSA signature over SHA-256(Quoted) under the PINNED AK, (d) the quote covers EXACTLY attestPCR in
// the SHA-256 bank (so a forger cannot launder the digest through a resettable PCR), and (e) that
// PCR's digest == H(0^32 || expected-D). Fail-closed on any mismatch. expectedDHex is the good
// composite digest the verifier computed from known-good TCB values out-of-band.
func cmdAttestVerify(envPath, expectedDHex, nonceHex, pinnedAK string) {
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

	// (0) PIN THE AK out-of-band. The envelope's AK is attacker-controllable, so it is trusted ONLY
	// after it bytewise-matches the operator-supplied expected AK (the per-box identity, captured TOFU
	// on first contact). A forger with a different TPM/key — or a MITM swapping the whole envelope —
	// supplies a non-matching AK and is rejected HERE, before the signature is ever checked under it.
	pinDER, err := resolveAKPin(pinnedAK)
	if err != nil {
		fatalf("attest verify: pinned AK: %v", err)
	}
	if !bytes.Equal(akDER, pinDER) {
		fatalf("attest verify: FAIL — envelope AK does not match the pinned AK (forged/untrusted box, or wrong box)")
	}

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
	qi, err := att.Attested.Quote()
	if err != nil {
		fatalf("attest verify: not a quote attestation: %v", err)
	}
	// (d) the quote must cover EXACTLY attestPCR in the SHA-256 bank. The quote's pcrDigest is
	// H(selected PCR VALUES) — the PCR INDEX is NOT in the digested bytes; it lives in pcrSelect. So
	// without this check a forger (or a root attacker who tampered attestPCR's history) could
	// TPM2_PCR_Reset a RESETTABLE PCR (16/23), extend the good D into it, and quote THAT — its
	// pcrDigest would equal the expected one and (e) would pass. Binding the SELECTION to the
	// extend-only PCR is what makes the non-resettability argument actually hold for the quote we check.
	sels := qi.PCRSelect.PCRSelections
	if len(sels) != 1 || sels[0].Hash != tpm2.TPMAlgSHA256 ||
		!bytes.Equal(sels[0].PCRSelect, pcrSelectBitmap(attestPCR)) {
		fatalf("attest verify: FAIL — quote does not cover exactly PCR %d (SHA-256); refusing a digest laundered through another/resettable PCR", attestPCR)
	}
	if env.PCR != attestPCR {
		fatalf("attest verify: FAIL — envelope PCR %d != expected PCR %d", env.PCR, attestPCR)
	}
	// (e) that PCR's digest == H(0^32 || expected-D) (single extend from a zero bank). With one PCR
	// selected the quote's pcrDigest is H(PCR-value) where PCR-value == H(0^32 || D); compute the same.
	want := pcrExtendFromZero(expectedD)
	wantQuoteDigest := sha256.Sum256(want)
	if !bytes.Equal(qi.PCRDigest.Buffer, wantQuoteDigest[:]) {
		fatalf("attest verify: FAIL — PCR digest mismatch: the box is NOT in the expected enforcing TCB state")
	}
	fmt.Printf("attest verify: OK — genuine TPM quote under the PINNED AK, fresh nonce, PCR %d (SHA-256) == expected enforcing-TCB state\n", env.PCR)
}

// cmdAttestMakeCredential is the OFF-BOX verifier step (no TPM): parse the box's enrollment request,
// BIND the wrap to the RECOMPUTED AK Name (never the box's claimed ak_name) and assert the AK pub we
// challenge is the SAME key that will be pinned (so a tampered box can't pin key A while proving
// possession of key B, nor claim a Name it doesn't hold), optionally validate the EK cert chain (bare
// metal), then MakeCredential a fresh secret encapsulated to the EK + bound to that Name. Writes the
// challenge JSON to stdout and the fresh secret (hex) to secretOutPath (held verifier-private — it is
// the per-round replay defense and is NEVER sent to the box).
func cmdAttestMakeCredential(reqPath, secretOutPath, ekCAArg string) {
	raw, err := os.ReadFile(reqPath)
	if err != nil {
		fatalf("attest make-credential: read request: %v", err)
	}
	var req enrollRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		fatalf("attest make-credential: parse request: %v", err)
	}
	ekPubBytes, err := hex.DecodeString(req.EKPubTPMT)
	if err != nil {
		fatalf("attest make-credential: ek_pub_tpmt hex: %v", err)
	}
	ekPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](ekPubBytes)
	if err != nil {
		fatalf("attest make-credential: parse EK pub: %v", err)
	}
	akPubBytes, err := hex.DecodeString(req.AKPubTPMT)
	if err != nil {
		fatalf("attest make-credential: ak_pub_tpmt hex: %v", err)
	}
	akPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](akPubBytes)
	if err != nil {
		fatalf("attest make-credential: parse AK pub: %v", err)
	}
	// recompute the AK Name from the pub area; reject a request whose claimed ak_name differs.
	name, err := tpm2.ObjectName(akPub)
	if err != nil {
		fatalf("attest make-credential: recompute AK Name: %v", err)
	}
	claimedName, _ := hex.DecodeString(req.AKName)
	if !bytes.Equal(name.Buffer, claimedName) {
		fatalf("attest make-credential: FAIL — request ak_name != the recomputed Name of ak_pub_tpmt (forged request)")
	}
	// the AK pub we challenge (TPMT_PUBLIC) must equal the PKIX pin-to-be; else the box could pin a
	// different key than it proves possession of.
	derFromTPMT, err := tpmtECCToPKIX(akPub)
	if err != nil {
		fatalf("attest make-credential: AK pub to PKIX: %v", err)
	}
	claimedDER, _ := hex.DecodeString(req.AKPubDER)
	if !bytes.Equal(derFromTPMT, claimedDER) {
		fatalf("attest make-credential: FAIL — ak_pub_der != ak_pub_tpmt (pinning a different key than challenged)")
	}
	// EK cert: bare metal validates the chain to a supplied EK-CA root + asserts cert-pub == EK-pub;
	// under swtpm (self-signed dev PKI) NOTE and skip — honest seam.
	if ekCAArg != "" {
		validateEKCertChain(req, derFromEKPub(ekPub), ekCAArg) // fatalf on any failure
	} else {
		fmt.Fprintln(os.Stderr, "attest make-credential: NOTE — no EK-CA trust anchor supplied; skipping EK-cert chain validation (swtpm self-signed dev PKI). Pass <ek-ca.pem> on bare metal.")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		fatalf("attest make-credential: rand: %v", err)
	}
	ekKey, err := tpm2.ImportEncapsulationKey(ekPub)
	if err != nil {
		fatalf("attest make-credential: import EK: %v", err)
	}
	idObject, encSecret, err := tpm2.CreateCredential(rand.Reader, ekKey, name.Buffer, secret)
	if err != nil {
		fatalf("attest make-credential: CreateCredential: %v", err)
	}
	// Persist the verifier's PRIVATE round-state: the secret AND the RECOMPUTED key the secret was
	// wrapped to (derFromTPMT == tpmtECCToPKIX(ak_pub_tpmt)), NOT the raw request field. enroll-verify
	// pins this, so the pinned key is provably the AK whose Name was credential-activated.
	round := verifierRound{Secret: hex.EncodeToString(secret), AKPubDER: hex.EncodeToString(derFromTPMT)}
	rb, _ := json.Marshal(round)
	if err := os.WriteFile(secretOutPath, rb, 0o600); err != nil {
		fatalf("attest make-credential: write round-state: %v", err)
	}
	chal := activationChallenge{CredBlob: hex.EncodeToString(idObject), EncSecret: hex.EncodeToString(encSecret)}
	out, _ := json.Marshal(chal)
	fmt.Println(string(out))
}

// cmdAttestEnrollVerify is the OFF-BOX final step: the box's recovered secret must bytewise-equal the
// fresh secret make-credential wrapped THIS round, and the pin written is the key make-credential
// bound that secret to — BOTH read from the same verifier-private round-state, so the pinned key is
// provably the AK whose Name the recovered secret proves possession of. There is no separately-
// supplied enrollRequest in the trust path (which could otherwise pin a different key than was
// possession-proven). Fail-closed on any mismatch.
func cmdAttestEnrollVerify(respPath, roundPath, outPinPath string) {
	rraw, err := os.ReadFile(respPath)
	if err != nil {
		fatalf("attest enroll-verify: read response: %v", err)
	}
	var resp activationResponse
	if err := json.Unmarshal(rraw, &resp); err != nil {
		fatalf("attest enroll-verify: parse response: %v", err)
	}
	recovered, err := hex.DecodeString(resp.RecoveredSecret)
	if err != nil {
		fatalf("attest enroll-verify: recovered_secret hex: %v", err)
	}
	rsraw, err := os.ReadFile(roundPath)
	if err != nil {
		fatalf("attest enroll-verify: read round-state: %v", err)
	}
	var round verifierRound
	if err := json.Unmarshal(rsraw, &round); err != nil {
		fatalf("attest enroll-verify: parse round-state: %v", err)
	}
	secret, err := hex.DecodeString(round.Secret)
	if err != nil {
		fatalf("attest enroll-verify: round secret hex: %v", err)
	}
	if len(secret) < 16 || !bytes.Equal(recovered, secret) {
		fatalf("attest enroll-verify: FAIL — recovered secret != this round's challenge secret (AK is NOT loaded in the genuine EK's TPM)")
	}
	// pin the key make-credential bound the secret to (recomputed from ak_pub_tpmt that round).
	der, err := hex.DecodeString(round.AKPubDER)
	if err != nil || len(round.AKPubDER) == 0 {
		fatalf("attest enroll-verify: round-state has no/invalid ak_pub_der")
	}
	if _, err := ecdsaPubFromDER(der); err != nil {
		fatalf("attest enroll-verify: round-state ak_pub_der is not a valid ECDSA pub: %v", err)
	}
	if err := os.WriteFile(outPinPath, []byte(round.AKPubDER+"\n"), 0o600); err != nil {
		fatalf("attest enroll-verify: write pin: %v", err)
	}
	fmt.Printf("attest enroll-verify: OK — AK is EK-rooted (credential-activation secret recovered); wrote EK-rooted pin to %s\n", outPinPath)
}

// validateEKCertChain is the BARE-METAL EK trust anchor (UNEXERCISED under swtpm, which has self-
// signed dev PKI): the EK cert must chain to the operator-supplied EK-CA root(s) AND its public key
// must equal the EK pub we are about to encapsulate to (so the cert vouches for THIS EK). Fail-closed.
func validateEKCertChain(req enrollRequest, ekPubDER []byte, ekCAArg string) {
	if req.EKCertDER == "" {
		fatalf("attest make-credential: FAIL — EK-CA supplied but the request carries no ek_cert_der")
	}
	certDER, err := hex.DecodeString(req.EKCertDER)
	if err != nil {
		fatalf("attest make-credential: ek_cert_der hex: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		fatalf("attest make-credential: parse EK cert: %v", err)
	}
	caPEM := ekCAArg
	if strings.HasPrefix(caPEM, "@") {
		b, err := os.ReadFile(caPEM[1:])
		if err != nil {
			fatalf("attest make-credential: read EK-CA: %v", err)
		}
		caPEM = string(b)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		fatalf("attest make-credential: EK-CA arg has no PEM certificates")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		fatalf("attest make-credential: FAIL — EK cert does not chain to the supplied EK-CA: %v", err)
	}
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		fatalf("attest make-credential: FAIL — EK cert public key is not ECDSA")
	}
	certPubDER, err := marshalPKIX(certPub)
	if err != nil {
		fatalf("attest make-credential: EK cert pub to PKIX: %v", err)
	}
	if !bytes.Equal(certPubDER, ekPubDER) {
		fatalf("attest make-credential: FAIL — EK cert public key != the EK pub being challenged (cert vouches for a different EK)")
	}
}

// tpmtECCToPKIX extracts the ECC point from a TPMT_PUBLIC and returns its PKIX (SubjectPublicKeyInfo)
// DER — the same encoding as the ADR-0019 AK pin.
func tpmtECCToPKIX(pub *tpm2.TPMTPublic) ([]byte, error) {
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

// derFromEKPub returns the EK pub's PKIX DER for the cert-pub == EK-pub binding (bare-metal path).
func derFromEKPub(pub *tpm2.TPMTPublic) []byte {
	der, err := tpmtECCToPKIX(pub)
	if err != nil {
		return nil // a non-ECC EK never matches an ECDSA cert pub -> validateEKCertChain fails closed
	}
	return der
}

// resolveAKPin loads the operator-supplied expected AK pub used to PIN the box identity: a PKIX DER
// hex string, or @path to a file holding that hex (mirroring verify-audit's pubkey discipline). It
// fails closed — an absent / garbled / non-ECDSA pin is a verify FAILURE, never a silent skip.
func resolveAKPin(arg string) ([]byte, error) {
	s := strings.TrimSpace(arg)
	if s == "" {
		return nil, fmt.Errorf("empty pin (pass the expected AK pub hex, or @file)")
	}
	if strings.HasPrefix(s, "@") {
		b, err := os.ReadFile(s[1:])
		if err != nil {
			return nil, err
		}
		s = strings.TrimSpace(string(b))
	}
	der, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("pinned AK must be PKIX DER hex (or @file): %w", err)
	}
	if _, err := ecdsaPubFromDER(der); err != nil {
		return nil, fmt.Errorf("pinned AK is not a valid ECDSA public key: %w", err)
	}
	return der, nil
}

// cmdAttestAKPub prints an envelope's AK pub (PKIX DER hex) — used to capture the per-box pin on a
// trusted first contact (TOFU): `attest akpub env.json > box-ak.hex`, then pass @box-ak.hex to verify.
func cmdAttestAKPub(envPath string) {
	raw, err := os.ReadFile(envPath)
	if err != nil {
		fatalf("attest akpub: read envelope: %v", err)
	}
	var env attestEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		fatalf("attest akpub: parse envelope: %v", err)
	}
	if env.AKPubDER == "" {
		fatalf("attest akpub: envelope has no ak_pub_der")
	}
	fmt.Println(env.AKPubDER)
}

// cmdAttestExpectedD is the OFF-BOX (no TPM, no maps) expected-digest derivation (ADR-0022): a relying
// party computes the digest D the box SHOULD extend, from the known-good collector binary + the
// expected ENFORCING posture — the SAME composeDigest the live box uses, so it matches byte-for-byte
// WITHOUT reading the box's `attest: extended` journal line. The posture is the ADR-0018 default-armed
// expectation: E0(bpf)+E2(socket_connect) ENFORCE, E1/E3 observe, tcb clean with exactly {root,
// collector, broker}. (Deliberately NOT "all-armed": E1/E3 are not armed by default, so requiring them
// would compute a D no healthy box ever extends.) Feed the byte-reproducible STRIPPED rootfs binary,
// which equals the running collector's /proc/self/exe on the read-only rootfs.
func cmdAttestExpectedD(binPath string) {
	exe, err := os.ReadFile(binPath)
	if err != nil {
		fatalf("attest expected-d: read collector binary: %v", err)
	}
	exeSum := sha256.Sum256(exe)
	flagVals := map[uint32]uint32{hookBPF: 1, hookConnect: 1} // ptrace/setuid/capset default 0 (observe)
	d := composeDigest(hex.EncodeToString(exeSum[:]), flagVals, expectedTCBCount, true)
	fmt.Println(hex.EncodeToString(d[:]))
}

func cmdAttest(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: bulkhead-collector attest extend | quote <nonce-hex> | akpub <env.json> | verify <env.json> <D-hex> <nonce-hex> <pin-hex|@file>")
		fmt.Fprintln(os.Stderr, "       EK-rooting (ADR-0020): ek | activate <challenge.json> | make-credential <request.json> <round-out> [ek-ca-pem|@file] | enroll-verify <response.json> <round-state> <out-pin>")
		fmt.Fprintln(os.Stderr, "       posture gate (ADR-0021): gate  (exit 0 = E0+E2 armed + tcb_clean; non-zero = fail-closed)")
		fmt.Fprintln(os.Stderr, "       reproducible expected-D (ADR-0022): expected-d <collector-binary>  (off-box D for `verify`, no journal)")
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
	case "akpub":
		// OFF-BOX: extract the AK pub from an envelope to PIN it (TOFU first contact).
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: bulkhead-collector attest akpub <envelope.json>")
			os.Exit(2)
		}
		cmdAttestAKPub(args[1])
	case "gate":
		// on-box: ask the collector (TCB) whether the box is in the expected enforcing posture. The
		// enforce_flags/tcb_cgroups reads EPERM from this non-TCB CLI cgroup under armed-E0, so they run
		// in the collector. controlRPCGate fail-closes FAST on a server ERR (not-armed), retrying only
		// the boot race. Exit non-zero (fatalf) on not-armed => the gate oneshot fails => fail-closed.
		ok, resp := controlRPCGate("ATTEST-GATE")
		if !ok {
			fatalf("attest gate: %s", resp)
		}
		fmt.Println(resp)
	case "expected-d":
		// OFF-BOX, no TPM/maps: derive the expected D from a known-good collector binary + the default-
		// armed posture (ADR-0022) — what a relying party feeds to `attest verify`, NOT the box journal.
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: bulkhead-collector attest expected-d <collector-binary>")
			os.Exit(2)
		}
		cmdAttestExpectedD(args[1])
	case "ek":
		// on-box: ask the collector (TCB) for the EK enrollment request (EK pub + cert + AK pub/Name).
		ok, resp := controlRPC("ATTEST-EK")
		if !ok {
			fatalf("attest ek: %s", resp)
		}
		fmt.Println(strings.TrimPrefix(resp, "OK "))
	case "activate":
		// on-box: feed the verifier's challenge to the collector (TCB) to ActivateCredential.
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: bulkhead-collector attest activate <challenge.json>")
			os.Exit(2)
		}
		craw, err := os.ReadFile(args[1])
		if err != nil {
			fatalf("attest activate: read challenge: %v", err)
		}
		var chal activationChallenge
		if err := json.Unmarshal(craw, &chal); err != nil {
			fatalf("attest activate: parse challenge: %v", err)
		}
		if chal.CredBlob == "" || chal.EncSecret == "" {
			fatalf("attest activate: challenge missing cred_blob/enc_secret")
		}
		ok, resp := controlRPC("ATTEST-ACTIVATE " + chal.CredBlob + " " + chal.EncSecret)
		if !ok {
			fatalf("attest activate: %s", resp)
		}
		fmt.Println(strings.TrimPrefix(resp, "OK "))
	case "make-credential":
		// OFF-BOX, no TPM: MakeCredential a fresh secret bound to the box's EK + AK Name; writes a
		// private round-state {secret, bound-AK-PKIX} to <round-out> for enroll-verify.
		if len(args) != 3 && len(args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: bulkhead-collector attest make-credential <request.json> <round-out-file> [ek-ca-pem|@file]")
			os.Exit(2)
		}
		ekCA := ""
		if len(args) == 4 {
			ekCA = args[3]
		}
		cmdAttestMakeCredential(args[1], args[2], ekCA)
	case "enroll-verify":
		// OFF-BOX, no TPM: secret equality vs make-credential's round-state -> write the EK-rooted pin.
		if len(args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: bulkhead-collector attest enroll-verify <response.json> <round-state-file> <out-pin-file>")
			os.Exit(2)
		}
		cmdAttestEnrollVerify(args[1], args[2], args[3])
	case "verify":
		// OFF-BOX: no TPM, no maps — runs anywhere (a relying party's machine). The PINNED AK binds
		// the proof to THE expected box; without it any genuine TPM could forge a PASS.
		if len(args) != 5 {
			fmt.Fprintln(os.Stderr, "usage: bulkhead-collector attest verify <envelope.json> <expected-digest-hex> <nonce-hex> <pinned-ak-pub-hex|@file>")
			os.Exit(2)
		}
		cmdAttestVerify(args[1], args[2], args[3], args[4])
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

// ctlAttestGate runs the posture predicate IN THE COLLECTOR (TCB) so its enforce_flags/tcb_cgroups
// bpf() reads survive armed-E0 — a non-TCB caller would EPERM, which is exactly what gives the gate
// teeth (the read itself is privileged/uncircumventable). Operator-only, like ctlAttestExtend.
func ctlAttestGate(reply func(string), cgPath string) {
	if isAgentCgroup(cgPath) {
		reply("ERR not-operator")
		return
	}
	armed, detail, err := gatePosture()
	if err != nil {
		reply("ERR " + err.Error())
		return
	}
	if !armed {
		reply("ERR not-armed " + detail)
		return
	}
	reply("OK " + detail)
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

// ctlAttestEK / ctlAttestActivate run the EK-cert credential-activation TPM ops IN THE COLLECTOR
// (TCB), operator-gated like ctlAttestQuote (handleControlConn already requires uid==0; an AGENT
// cgroup is rejected — a jailed lineage must never drive enrollment).
func ctlAttestEK(reply func(string), cgPath string) {
	if isAgentCgroup(cgPath) {
		reply("ERR not-operator")
		return
	}
	req, err := doAttestEK()
	if err != nil {
		reply("ERR " + err.Error())
		return
	}
	reply("OK " + req)
}

func ctlAttestActivate(reply func(string), cgPath string, f []string) {
	if isAgentCgroup(cgPath) {
		reply("ERR not-operator")
		return
	}
	if len(f) != 3 {
		reply("ERR protocol")
		return
	}
	resp, err := doAttestActivate(f[1], f[2])
	if err != nil {
		reply("ERR " + err.Error())
		return
	}
	reply("OK " + resp)
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
	return tpmtECCToPKIX(pub)
}
