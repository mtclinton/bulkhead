// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"fmt"
	"testing"
)

// ---- fakes (inject the crypto engine + transport so the state machine is deterministic) ---------------

type fakeVerifier struct {
	pin        string
	quoteErr   error
	chainErrFn func(path, pub, since, expect string) error
	akpubCalls int
	lastSince  string
	lastExpect string
}

func (f *fakeVerifier) AKPub(string) (string, error)            { f.akpubCalls++; return f.pin, nil }
func (f *fakeVerifier) ExpectedD(string) (string, error)        { return "d0d0", nil }
func (f *fakeVerifier) VerifyQuote(_, _, _, _ string) error     { return f.quoteErr }
func (f *fakeVerifier) VerifyChain(path, pub, domain, since, expect string) error {
	f.lastSince, f.lastExpect = since, expect
	if f.chainErrFn != nil {
		return f.chainErrFn(path, pub, since, expect)
	}
	return nil
}

type fakeTransport struct {
	quote, log         []byte
	quoteErr, logErr   error
}

func (f *fakeTransport) Fetch(_ string, subs map[string]string) ([]byte, error) {
	if _, isQuote := subs["nonce"]; isQuote {
		return f.quote, f.quoteErr
	}
	return f.log, f.logErr // a chain fetch ({chain} substitution)
}

// helpers
func env(coll, ctrl, broker string) []byte {
	return []byte(fmt.Sprintf(`{"head_collector_hex":%q,"head_control_hex":%q,"head_broker_hex":%q}`, coll, ctrl, broker))
}

func ctrlDevice() *Device {
	return &Device{
		Name: "box1", QuoteCmd: "ssh box1 quote {nonce}", FetchChainCmd: "ssh box1 cat {chain}",
		ExpectedD: "d0d0",
		Chains:    []Chain{{Domain: "control", RemotePath: "/data/control.jsonl", HeadField: "head_control_hex"}},
	}
}

func cfg() *Config { return &Config{MissedThreshold: 2, IntervalSeconds: 1} }

func freshState() *deviceState { return &deviceState{Chains: map[string]chainState{}} }

func kinds(as []Alert) (out []string) {
	for _, a := range as {
		out = append(out, a.Kind)
	}
	return
}

// ---- tests --------------------------------------------------------------------------------------------

func TestFirstObservationPinsHeadAndAK(t *testing.T) {
	v := &fakeVerifier{pin: "ak0001"}
	tr := &fakeTransport{quote: env("c0", "ctrlTIP", "b0"), log: []byte("log")}
	st := freshState()
	al := pollDevice(cfg(), ctrlDevice(), st, v, tr, "nonceA", 100, t.TempDir())

	if len(al) != 0 {
		t.Fatalf("first obs should not alert, got %v", kinds(al))
	}
	if st.AKPinHex != "ak0001" || v.akpubCalls != 1 {
		t.Fatalf("AK pin not TOFU-captured: pin=%q calls=%d", st.AKPinHex, v.akpubCalls)
	}
	if st.Chains["control"].PinnedHead != "ctrlTIP" {
		t.Fatalf("HEAD not pinned: %q", st.Chains["control"].PinnedHead)
	}
	if v.lastSince != "" || v.lastExpect != "ctrlTIP" {
		t.Fatalf("first obs: want no --since + --expect-tip=ctrlTIP, got since=%q expect=%q", v.lastSince, v.lastExpect)
	}
}

func TestAdvanceMovesPinAndAnchorsPrior(t *testing.T) {
	v := &fakeVerifier{pin: "ak0001"}
	tr := &fakeTransport{quote: env("c1", "ctrlTIP2", "b1"), log: []byte("log")}
	st := &deviceState{AKPinHex: "ak0001", Chains: map[string]chainState{"control": {PinnedHead: "ctrlTIP"}}}
	al := pollDevice(cfg(), ctrlDevice(), st, v, tr, "nonceB", 200, t.TempDir())

	if len(al) != 0 {
		t.Fatalf("clean advance should not alert, got %v", kinds(al))
	}
	if v.akpubCalls != 0 {
		t.Fatalf("AK already pinned; must not re-TOFU")
	}
	if v.lastSince != "ctrlTIP" || v.lastExpect != "ctrlTIP2" {
		t.Fatalf("advance must anchor prior + expect new: since=%q expect=%q", v.lastSince, v.lastExpect)
	}
	if st.Chains["control"].PinnedHead != "ctrlTIP2" {
		t.Fatalf("pin not advanced: %q", st.Chains["control"].PinnedHead)
	}
}

func TestRewindAlertsAndDoesNotAdvance(t *testing.T) {
	v := &fakeVerifier{pin: "ak0001", chainErrFn: func(_, _, _, _ string) error {
		return fmt.Errorf("REWOUND: prior HEAD not a verified ancestor")
	}}
	tr := &fakeTransport{quote: env("c1", "forkedTIP", "b1"), log: []byte("truncated-log")}
	st := &deviceState{AKPinHex: "ak0001", Chains: map[string]chainState{"control": {PinnedHead: "ctrlTIP"}}}
	al := pollDevice(cfg(), ctrlDevice(), st, v, tr, "nonceC", 300, t.TempDir())

	if k := kinds(al); len(k) != 1 || k[0] != "chain-rewind-or-fail" {
		t.Fatalf("rewind must alert chain-rewind-or-fail, got %v", k)
	}
	if al[0].Domain != "control" {
		t.Fatalf("alert domain: %q", al[0].Domain)
	}
	if st.Chains["control"].PinnedHead != "ctrlTIP" {
		t.Fatalf("rewind must NOT advance the pin (keep last-good anchor); got %q", st.Chains["control"].PinnedHead)
	}
}

func TestQuoteVerifyFailureAlertsAndCounts(t *testing.T) {
	v := &fakeVerifier{pin: "ak0001", quoteErr: fmt.Errorf("PCR14 mismatch")}
	tr := &fakeTransport{quote: env("c0", "ctrlTIP", "b0"), log: []byte("log")}
	st := &deviceState{AKPinHex: "ak0001", Chains: map[string]chainState{}}
	al := pollDevice(cfg(), ctrlDevice(), st, v, tr, "nonceD", 400, t.TempDir())

	if k := kinds(al); len(k) != 1 || k[0] != "quote-verify-failed" {
		t.Fatalf("want quote-verify-failed, got %v", k)
	}
	if st.Misses != 1 {
		t.Fatalf("a bad quote should count as a miss, got %d", st.Misses)
	}
	if v.lastExpect != "" {
		t.Fatalf("chains must NOT be processed after a failed quote")
	}
}

func TestMissedAttestationFiresAtThreshold(t *testing.T) {
	v := &fakeVerifier{pin: "ak0001"}
	tr := &fakeTransport{quoteErr: fmt.Errorf("ssh: connection refused")}
	st := &deviceState{AKPinHex: "ak0001", Chains: map[string]chainState{}}
	c := cfg() // MissedThreshold = 2

	al1 := pollDevice(c, ctrlDevice(), st, v, tr, "n1", 500, t.TempDir())
	if len(al1) != 0 {
		t.Fatalf("one silent poll is below threshold, got %v", kinds(al1))
	}
	if st.Misses != 1 {
		t.Fatalf("misses=%d", st.Misses)
	}
	al2 := pollDevice(c, ctrlDevice(), st, v, tr, "n2", 600, t.TempDir())
	if k := kinds(al2); len(k) != 1 || k[0] != "missed-attestation" {
		t.Fatalf("second silent poll must alert missed-attestation, got %v", k)
	}
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := &deviceState{AKPinHex: "akZ", LastOK: 42, Misses: 1,
		Chains: map[string]chainState{"broker": {PinnedHead: "bTIP", LastUpdate: 7}}}
	if err := saveState(dir, "box/../weird name", in); err != nil {
		t.Fatal(err)
	}
	out := loadState(dir, "box/../weird name")
	if out.AKPinHex != "akZ" || out.Chains["broker"].PinnedHead != "bTIP" || out.LastOK != 42 {
		t.Fatalf("round-trip lost data: %+v", out)
	}
}

func TestRecoveryAfterMiss(t *testing.T) {
	// a missed poll then a good poll resets the counter (no stuck-alert).
	dev := ctrlDevice()
	v := &fakeVerifier{pin: "ak0001"}
	st := &deviceState{AKPinHex: "ak0001", Misses: 1, Chains: map[string]chainState{"control": {PinnedHead: "t0"}}}
	tr := &fakeTransport{quote: env("c", "t1", "b"), log: []byte("log")}
	al := pollDevice(cfg(), dev, st, v, tr, "n", 700, t.TempDir())
	if len(al) != 0 || st.Misses != 0 {
		t.Fatalf("a good poll must clear misses + not alert: misses=%d alerts=%v", st.Misses, kinds(al))
	}
}

func TestLastHexToken(t *testing.T) {
	cases := map[string]string{
		"OK aabbccddeeff00112233445566778899":                                    "aabbccddeeff00112233445566778899",
		"D=deadbeefdeadbeefdeadbeefdeadbeef":                                      "deadbeefdeadbeefdeadbeefdeadbeef",
		"verified\nexpected-d xyz nothex here":                                    "",      // too-short / non-hex tokens ignored
		"aabbccdd":                                                                "",      // 8 chars < 32-char floor
		"first 00112233445566778899aabbccddeeff then ffeeddccbbaa00998877665544332211": "ffeeddccbbaa00998877665544332211", // last valid wins
	}
	for in, want := range cases {
		if got := lastHexToken(in); got != want {
			t.Errorf("lastHexToken(%q)=%q want %q", in, got, want)
		}
	}
}
