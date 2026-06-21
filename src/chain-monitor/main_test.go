// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- fakes (inject the crypto engine + transport so the state machine is deterministic) ---------------

type fakeVerifier struct {
	pin        string
	quoteErr   error
	chainErrFn func(path, pub, since, expect string) error
	chainTip   string // the verify-audit-authenticated tip returned when there is no --expect-tip (no quote)
	akpubCalls int
	lastSince  string
	lastExpect string
}

func (f *fakeVerifier) AKPub(string) (string, error)        { f.akpubCalls++; return f.pin, nil }
func (f *fakeVerifier) ExpectedD(string) (string, error)    { return "d0d0", nil }
func (f *fakeVerifier) VerifyQuote(_, _, _, _ string) error { return f.quoteErr }

// VerifyChain models the real tool: on success it returns the AUTHENTICATED tip. With --expect-tip set
// (a fresh quote), verify-audit asserts tip==expect, so the fake returns expect; without it (independent
// witness) it returns the configured chainTip, defaulting to the --since anchor (an idle, unchanged chain).
func (f *fakeVerifier) VerifyChain(path, pub, domain, since, expect string) (string, error) {
	f.lastSince, f.lastExpect = since, expect
	if f.chainErrFn != nil {
		if err := f.chainErrFn(path, pub, since, expect); err != nil {
			return "", err
		}
	}
	switch {
	case expect != "":
		return expect, nil
	case f.chainTip != "":
		return f.chainTip, nil
	default:
		return since, nil
	}
}

type fakeTransport struct {
	quote, log       []byte
	quoteErr, logErr error
	fetchFn          func(cmd string, subs map[string]string) ([]byte, error) // overrides the simple fields when set
}

func (f *fakeTransport) Fetch(cmd string, subs map[string]string) ([]byte, error) {
	if f.fetchFn != nil {
		return f.fetchFn(cmd, subs)
	}
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

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
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

func TestQuoteVerifyFailureStillWitnessesChain(t *testing.T) {
	// A quote-verify failure counts as a miss AND alerts — but it no longer SKIPS the chains ([73]): the HEAD
	// witness still runs via --since (no --expect-tip without a fresh quote), so a box that stops attesting but
	// serves a truncated chain is still caught. A CLEAN chain here adds no chain alert.
	v := &fakeVerifier{pin: "ak0001", quoteErr: fmt.Errorf("PCR14 mismatch")}
	tr := &fakeTransport{quote: env("c0", "ctrlTIP", "b0"), log: []byte("r1\nr2\n")}
	st := &deviceState{AKPinHex: "ak0001", Chains: map[string]chainState{"control": {PinnedHead: "ctrlTIP"}}}
	al := pollDevice(cfg(), ctrlDevice(), st, v, tr, "nonceD", 400, t.TempDir())

	if k := kinds(al); len(k) != 1 || k[0] != "quote-verify-failed" {
		t.Fatalf("want exactly quote-verify-failed (a clean witnessed chain adds none), got %v", k)
	}
	if st.Misses != 1 {
		t.Fatalf("a bad quote should count as a miss, got %d", st.Misses)
	}
	if v.lastSince != "ctrlTIP" || v.lastExpect != "" {
		t.Fatalf("the chain must STILL be witnessed via --since with no --expect-tip: since=%q expect=%q", v.lastSince, v.lastExpect)
	}
}

func TestTailTruncationDetectedWithoutFreshQuote(t *testing.T) {
	// [73] core: a box that has STOPPED attesting (quote won't verify) but serves a TAIL-TRUNCATED chain. The
	// prior-pinned HEAD is gone from the chain => verify-audit returns REWOUND, and the witness alarms within
	// one poll WITHOUT relying on a fresh quote. The pin is kept (not advanced) as the last-good anchor.
	v := &fakeVerifier{pin: "ak0001", quoteErr: fmt.Errorf("no quote responder"),
		chainErrFn: func(_, _, since, _ string) error {
			return fmt.Errorf("REWOUND: prior HEAD %s not a verified ancestor (tail truncated)", since)
		}}
	tr := &fakeTransport{quote: env("c1", "x", "b1"), log: []byte("r1\n")}
	st := &deviceState{AKPinHex: "ak0001", Chains: map[string]chainState{"control": {PinnedHead: "ctrlTIP"}}}
	al := pollDevice(cfg(), ctrlDevice(), st, v, tr, "n", 800, t.TempDir())

	if !contains(kinds(al), "chain-rewind-or-fail") {
		t.Fatalf("a tail-truncation must alarm chain-rewind-or-fail even with no fresh quote, got %v", kinds(al))
	}
	if v.lastExpect != "" {
		t.Fatalf("no fresh quote => witness via --since only (--expect-tip must be empty), got %q", v.lastExpect)
	}
	if st.Chains["control"].PinnedHead != "ctrlTIP" {
		t.Fatalf("a rewind must NOT advance the pin; got %q", st.Chains["control"].PinnedHead)
	}
	// the enriched detail must name the dual cause so the operator isn't told it's definitely an attack.
	var d string
	for _, a := range al {
		if a.Kind == "chain-rewind-or-fail" {
			d = a.Detail
		}
	}
	if !strings.Contains(d, "rotation") || !strings.Contains(d, "re-anchor") {
		t.Fatalf("rewind detail must name the benign-rotation dual cause + the re-anchor remedy, got %q", d)
	}
}

func TestWitnessAdvancesPinToVerifiedTipWithoutQuote(t *testing.T) {
	// With no usable quote a CLEAN chain still advances the pin to the verify-audit-authenticated tip, so the
	// next poll's --since anchor stays recent (inside the ADR-0040 retained window) and rotation cannot prune
	// it before the next check — the property that keeps legitimate rotation from false-positiving.
	v := &fakeVerifier{pin: "ak0001", quoteErr: fmt.Errorf("quote down"), chainTip: "ctrlTIP_NEW"}
	tr := &fakeTransport{quote: env("c1", "ignored", "b1"), log: []byte("r1\nr2\nr3\n")}
	st := &deviceState{AKPinHex: "ak0001", Chains: map[string]chainState{"control": {PinnedHead: "ctrlTIP"}}}
	al := pollDevice(cfg(), ctrlDevice(), st, v, tr, "n", 900, t.TempDir())

	if contains(kinds(al), "chain-rewind-or-fail") || contains(kinds(al), "fetch-failed") {
		t.Fatalf("a clean witnessed chain must not chain-alarm, got %v", kinds(al))
	}
	if v.lastSince != "ctrlTIP" || v.lastExpect != "" {
		t.Fatalf("witness via --since only: since=%q expect=%q", v.lastSince, v.lastExpect)
	}
	if st.Chains["control"].PinnedHead != "ctrlTIP_NEW" {
		t.Fatalf("pin must advance to the verified tip without a quote; got %q", st.Chains["control"].PinnedHead)
	}
}

func TestQuoteVerifiedButEmptyHeadFieldWitnessesNotAlarms(t *testing.T) {
	// A verified quote that binds NO head for this chain (head_control_hex == "") is not an error: it just
	// means no --expect-tip this cycle. The chain is still witnessed via --since and must NOT spuriously alarm.
	v := &fakeVerifier{pin: "ak0001", chainTip: "ctrlTIP2"}
	tr := &fakeTransport{quote: env("c", "", "b"), log: []byte("r1\nr2\n")}
	st := &deviceState{AKPinHex: "ak0001", Chains: map[string]chainState{"control": {PinnedHead: "ctrlTIP"}}}
	al := pollDevice(cfg(), ctrlDevice(), st, v, tr, "n", 950, t.TempDir())

	if len(al) != 0 {
		t.Fatalf("an empty bound HEAD must not alarm (witness via --since), got %v", kinds(al))
	}
	if v.lastSince != "ctrlTIP" || v.lastExpect != "" {
		t.Fatalf("witness via --since only when the head field is empty: since=%q expect=%q", v.lastSince, v.lastExpect)
	}
	if st.Chains["control"].PinnedHead != "ctrlTIP2" {
		t.Fatalf("pin should advance to the verified tip; got %q", st.Chains["control"].PinnedHead)
	}
}

func TestPerChainFetchFailureWhenReachable(t *testing.T) {
	// The box answers the quote (reachable) but a chain fetch fails: flag fetch-failed, leave the chain
	// unwitnessed this interval (no metric), and keep the prior pin.
	v := &fakeVerifier{pin: "ak0001"}
	tr := &fakeTransport{quote: env("c", "t1", "b"), logErr: fmt.Errorf("ssh: cat: no such file")}
	st := &deviceState{AKPinHex: "ak0001", Chains: map[string]chainState{"control": {PinnedHead: "ctrlTIP"}}}
	al := pollDevice(cfg(), ctrlDevice(), st, v, tr, "n", 960, t.TempDir())

	if !contains(kinds(al), "fetch-failed") {
		t.Fatalf("a reachable box with a failed chain fetch must alert fetch-failed, got %v", kinds(al))
	}
	if _, ok := st.Metrics.Chains["control"]; ok {
		t.Fatalf("an unfetched chain must not be marked witnessed")
	}
	if st.Chains["control"].PinnedHead != "ctrlTIP" {
		t.Fatalf("an unfetched chain must keep its prior pin; got %q", st.Chains["control"].PinnedHead)
	}
}

func TestGenesisHeadRoundTrips(t *testing.T) {
	// An empty chain attests the genesis HEAD (64 zero hex). It must pin + re-verify across polls without
	// alarming (the real verify-audit treats --since=<zeros> as a CLEAN genesis ancestor).
	zeros := strings.Repeat("0", 64)
	dev := ctrlDevice()
	v := &fakeVerifier{pin: "ak0001"}
	st := freshState()
	st.AKPinHex = "ak0001"
	tr := &fakeTransport{quote: env("c", zeros, "b"), log: []byte("")}
	if al := pollDevice(cfg(), dev, st, v, tr, "n1", 100, t.TempDir()); len(al) != 0 {
		t.Fatalf("genesis poll 1 must not alarm, got %v", kinds(al))
	}
	if st.Chains["control"].PinnedHead != zeros {
		t.Fatalf("genesis HEAD not pinned: %q", st.Chains["control"].PinnedHead)
	}
	if al := pollDevice(cfg(), dev, st, v, tr, "n2", 200, t.TempDir()); len(al) != 0 {
		t.Fatalf("genesis poll 2 (since=zeros) must not alarm, got %v", kinds(al))
	}
}

func TestMissedAttestationFiresAtThreshold(t *testing.T) {
	v := &fakeVerifier{pin: "ak0001"}
	tr := &fakeTransport{quoteErr: fmt.Errorf("ssh: connection refused"), logErr: fmt.Errorf("ssh: connection refused")}
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
		t.Fatalf("second silent poll must alert missed-attestation (no double chain noise), got %v", k)
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

func TestMetricsDerivedFromPoll(t *testing.T) {
	// green: reachable + attested + chain verified; record count derived from the fetched log.
	v := &fakeVerifier{pin: "ak"}
	tr := &fakeTransport{quote: env("c", "t1", "b"), log: []byte("r1\nr2\nr3\n")}
	st := &deviceState{AKPinHex: "ak", Chains: map[string]chainState{"control": {PinnedHead: "t0"}}}
	pollDevice(cfg(), ctrlDevice(), st, v, tr, "n", 100, t.TempDir())
	if st.Metrics == nil || st.Metrics.Reachable != 1 || st.Metrics.AttestOK != 1 {
		t.Fatalf("green: reachable/attest not set: %+v", st.Metrics)
	}
	if cm := st.Metrics.Chains["control"]; cm.Records != 3 || cm.VerifyOK != 1 || cm.Witnessed != 1 {
		t.Fatalf("green: chain metric wrong: %+v", cm)
	}

	// rewind: chain verify fails -> VerifyOK 0, but the HEAD was still ingested -> Witnessed 1; still attested.
	v2 := &fakeVerifier{pin: "ak", chainErrFn: func(_, _, _, _ string) error { return fmt.Errorf("REWOUND") }}
	st2 := &deviceState{AKPinHex: "ak", Chains: map[string]chainState{"control": {PinnedHead: "t0"}}}
	pollDevice(cfg(), ctrlDevice(), st2, v2, &fakeTransport{quote: env("c", "t1", "b"), log: []byte("r1\nr2\n")}, "n", 100, t.TempDir())
	if cm := st2.Metrics.Chains["control"]; cm.VerifyOK != 0 || cm.Witnessed != 1 || cm.Records != 2 {
		t.Fatalf("rewind chain metric: %+v", cm)
	}
	if st2.Metrics.AttestOK != 1 {
		t.Fatalf("rewind should still record AttestOK=1")
	}

	// missed: no quote AND the chain unreachable -> reachable 0, attest 0, no chain witnessed (fetch suppressed).
	st3 := &deviceState{AKPinHex: "ak", Chains: map[string]chainState{}}
	pollDevice(cfg(), ctrlDevice(), st3, &fakeVerifier{pin: "ak"}, &fakeTransport{quoteErr: fmt.Errorf("down"), logErr: fmt.Errorf("down")}, "n", 100, t.TempDir())
	if st3.Metrics.Reachable != 0 || st3.Metrics.AttestOK != 0 {
		t.Fatalf("missed: %+v", st3.Metrics)
	}
	if len(st3.Metrics.Chains) != 0 {
		t.Fatalf("a fully-silent box must not witness any chain, got %+v", st3.Metrics.Chains)
	}
}

func TestRenderMetrics(t *testing.T) {
	states := map[string]*deviceState{
		"box1": {Misses: 0, Metrics: &pollMetrics{Reachable: 1, AttestOK: 1, Chains: map[string]chainMetric{"control": {Records: 9, Witnessed: 1, VerifyOK: 1}}}},
		"box2": {Misses: 2, Metrics: &pollMetrics{Reachable: 0, AttestOK: 0, Chains: map[string]chainMetric{}}},
	}
	out := renderMetrics(states, 1234)
	for _, want := range []string{
		`bulkhead_device_reachable{device="box1"} 1`,
		`bulkhead_attestation_ok{device="box1"} 1`,
		`bulkhead_chain_records{device="box1",chain="control"} 9`,
		`bulkhead_chain_witnessed{device="box1",chain="control"} 1`,
		`bulkhead_chain_verify_ok{device="box1",chain="control"} 1`,
		`bulkhead_device_reachable{device="box2"} 0`,
		`bulkhead_device_missed_polls{device="box2"} 2`,
		`bulkhead_monitor_last_run_unixtime 1234`,
		"# TYPE bulkhead_chain_witnessed gauge",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("renderMetrics missing line: %s", want)
		}
	}
}

func TestSegmentedChainFetchReconstructsLayout(t *testing.T) {
	// [34]: the device exposes a segment-list command. The monitor must fetch all retained sealed segments +
	// the live file and mirror the on-box <base>.NNNNNN names into a per-domain dir, so verify-audit (which
	// lists those siblings) reconstructs a ROTATED chain. Records sum across all fetched files.
	dev := ctrlDevice()
	dev.ListSegmentsCmd = "ssh box ls {chain}.[0-9]*"
	dev.Chains[0].RemotePath = "/data/audit/control.jsonl"
	live := dev.Chains[0].RemotePath
	segList := live + ".000002\n" + live + ".000003\n" // 000001 already pruned (oldest retained = 000002)
	files := map[string]string{
		live:             "liveR1\nliveR2\n",
		live + ".000002": "s2r1\ns2r2\n",
		live + ".000003": "s3r1\n",
	}
	tr := &fakeTransport{fetchFn: func(cmd string, subs map[string]string) ([]byte, error) {
		if _, isQuote := subs["nonce"]; isQuote {
			return env("c", "ctrlTIP", "b"), nil
		}
		if cmd == dev.ListSegmentsCmd {
			return []byte(segList), nil
		}
		return []byte(files[subs["chain"]]), nil
	}}
	v := &fakeVerifier{pin: "ak", chainTip: "ctrlTIP"}
	wd := t.TempDir()
	st := &deviceState{AKPinHex: "ak", Chains: map[string]chainState{}}
	al := pollDevice(cfg(), dev, st, v, tr, "n", 100, wd)

	if contains(kinds(al), "fetch-failed") || contains(kinds(al), "chain-rewind-or-fail") {
		t.Fatalf("a clean segmented fetch must not alarm, got %v", kinds(al))
	}
	dd := filepath.Join(wd, "control")
	for _, f := range []string{"control.jsonl", "control.jsonl.000002", "control.jsonl.000003"} {
		if _, err := os.Stat(filepath.Join(dd, f)); err != nil {
			t.Fatalf("reconstructed dir missing %s: %v", f, err)
		}
	}
	if cm := st.Metrics.Chains["control"]; cm.Records != 5 {
		t.Fatalf("records must sum across the retained segments + live file (2+2+1=5), got %d", cm.Records)
	}
}

func TestSegmentRotationRaceSkipsVerdict(t *testing.T) {
	// [34]: if a rotation seals/prunes a segment WHILE the monitor is fetching the multi-file chain, the
	// off-box snapshot is inconsistent — the re-list differs from the first list, so the monitor skips the
	// verdict (no alarm, no advance, not marked verified) and re-checks next poll. This is NOT a truncation.
	dev := ctrlDevice()
	dev.ListSegmentsCmd = "ssh box ls {chain}.[0-9]*"
	dev.Chains[0].RemotePath = "/data/audit/control.jsonl"
	live := dev.Chains[0].RemotePath
	listCalls := 0
	tr := &fakeTransport{fetchFn: func(cmd string, subs map[string]string) ([]byte, error) {
		if _, isQuote := subs["nonce"]; isQuote {
			return env("c", "ctrlTIP", "b"), nil
		}
		if cmd == dev.ListSegmentsCmd {
			listCalls++
			if listCalls == 1 {
				return []byte(live + ".000001\n"), nil
			}
			return []byte(live + ".000001\n" + live + ".000002\n"), nil // re-list shows a NEW segment => rotation raced
		}
		return []byte("r1\n"), nil
	}}
	v := &fakeVerifier{pin: "ak", chainTip: "ctrlTIP"}
	st := &deviceState{AKPinHex: "ak", Chains: map[string]chainState{"control": {PinnedHead: "ctrlTIP"}}}
	al := pollDevice(cfg(), dev, st, v, tr, "n", 100, t.TempDir())

	if contains(kinds(al), "chain-rewind-or-fail") {
		t.Fatalf("a rotation race must NOT alarm, got %v", kinds(al))
	}
	if _, ok := st.Metrics.Chains["control"]; ok {
		t.Fatalf("a raced poll must not mark the chain witnessed/verified, got %+v", st.Metrics.Chains)
	}
	if st.Chains["control"].PinnedHead != "ctrlTIP" {
		t.Fatalf("a raced poll must not advance the pin, got %q", st.Chains["control"].PinnedHead)
	}
	if v.lastSince != "" || v.lastExpect != "" {
		t.Fatalf("a raced poll must not call verify-audit, got since=%q expect=%q", v.lastSince, v.lastExpect)
	}
}

func TestConsecutiveSegmentRacesAlarm(t *testing.T) {
	// [34] evasion guard: a box that re-rotates EVERY poll (segment set differs every fetch) would perpetually
	// dodge a consistent snapshot. After maxConsecutiveRaces in a row the monitor must ALARM chain-fetch-unstable.
	dev := ctrlDevice()
	dev.ListSegmentsCmd = "ssh box ls {chain}.[0-9]*"
	dev.Chains[0].RemotePath = "/data/audit/control.jsonl"
	live := dev.Chains[0].RemotePath
	listCalls := 0
	tr := &fakeTransport{fetchFn: func(cmd string, subs map[string]string) ([]byte, error) {
		if _, isQuote := subs["nonce"]; isQuote {
			return env("c", "ctrlTIP", "b"), nil
		}
		if cmd == dev.ListSegmentsCmd {
			listCalls++ // a DIFFERENT segment number every list call => list1 != list2 every poll => always raced
			return []byte(fmt.Sprintf("%s.%06d\n", live, listCalls)), nil
		}
		return []byte("r1\n"), nil
	}}
	v := &fakeVerifier{pin: "ak", chainTip: "ctrlTIP"}
	st := &deviceState{AKPinHex: "ak", Chains: map[string]chainState{}}
	for i := int64(1); i <= 2; i++ {
		if al := pollDevice(cfg(), dev, st, v, tr, "n", i, t.TempDir()); contains(kinds(al), "chain-fetch-unstable") {
			t.Fatalf("poll %d: must NOT alarm before maxConsecutiveRaces, got %v", i, kinds(al))
		}
	}
	if al := pollDevice(cfg(), dev, st, v, tr, "n", 3, t.TempDir()); !contains(kinds(al), "chain-fetch-unstable") {
		t.Fatalf("the 3rd consecutive race must alarm chain-fetch-unstable, got %v", kinds(al))
	}
}

func TestDuplicateSegmentNumberRejected(t *testing.T) {
	// [34] security: a box that lists the SAME segment number from two paths (basenames collide) must be
	// rejected, not silently resolved — a hostile box must not choose which signed segment we verify.
	dev := ctrlDevice()
	dev.ListSegmentsCmd = "ssh box ls {chain}.[0-9]*"
	dev.Chains[0].RemotePath = "/data/audit/control.jsonl"
	live := dev.Chains[0].RemotePath
	tr := &fakeTransport{fetchFn: func(cmd string, subs map[string]string) ([]byte, error) {
		if _, isQuote := subs["nonce"]; isQuote {
			return env("c", "ctrlTIP", "b"), nil
		}
		if cmd == dev.ListSegmentsCmd {
			return []byte(live + ".000001\n/tmp/forged/" + filepath.Base(live) + ".000001\n"), nil // dup number 000001
		}
		return []byte("r1\n"), nil
	}}
	v := &fakeVerifier{pin: "ak", chainTip: "ctrlTIP"}
	st := &deviceState{AKPinHex: "ak", Chains: map[string]chainState{}}
	al := pollDevice(cfg(), dev, st, v, tr, "n", 1, t.TempDir())
	if !contains(kinds(al), "fetch-failed") {
		t.Fatalf("a duplicate segment number must be rejected (fetch-failed), got %v", kinds(al))
	}
	if v.lastSince != "" || v.lastExpect != "" {
		t.Fatalf("a rejected segment list must not reach verify-audit")
	}
}

func TestOversizedChainFileRejected(t *testing.T) {
	// [34] security: a hostile box must not OOM the monitor with a giant "chain file".
	old := maxChainFileBytes
	maxChainFileBytes = 8
	defer func() { maxChainFileBytes = old }()
	tr := &fakeTransport{quote: env("c", "ctrlTIP", "b"), log: []byte("way more than eight bytes")}
	v := &fakeVerifier{pin: "ak", chainTip: "ctrlTIP"}
	st := &deviceState{AKPinHex: "ak", Chains: map[string]chainState{"control": {PinnedHead: "ctrlTIP"}}}
	al := pollDevice(cfg(), ctrlDevice(), st, v, tr, "n", 1, t.TempDir())
	if !contains(kinds(al), "fetch-failed") {
		t.Fatalf("an oversized chain file must be rejected (fetch-failed), got %v", kinds(al))
	}
}

func TestTipFromVerifyOutput(t *testing.T) {
	tip := strings.Repeat("ab", 32) // 64 hex
	cases := map[string]string{
		"verify-audit: OK — 9 record(s) verified for /x [key: k, domain: control], tip=" + tip: tip,
		"verify-audit: OK — 0 record(s) ... tip=" + strings.Repeat("0", 64):                    strings.Repeat("0", 64),
		"tip=" + strings.ToUpper(tip):    tip, // normalized to lower
		"no tip on this line":            "",
		"tip=tooshort":                   "",
		"tip=" + strings.Repeat("z", 64): "", // 64 chars but not hex
	}
	for in, want := range cases {
		if got := tipFromVerifyOutput(in); got != want {
			t.Errorf("tipFromVerifyOutput(%q)=%q want %q", in, got, want)
		}
	}
}

func TestLastHexToken(t *testing.T) {
	cases := map[string]string{
		"OK aabbccddeeff00112233445566778899":  "aabbccddeeff00112233445566778899",
		"D=deadbeefdeadbeefdeadbeefdeadbeef":   "deadbeefdeadbeefdeadbeefdeadbeef",
		"verified\nexpected-d xyz nothex here": "", // too-short / non-hex tokens ignored
		"aabbccdd":                             "", // 8 chars < 32-char floor
		"first 00112233445566778899aabbccddeeff then ffeeddccbbaa00998877665544332211": "ffeeddccbbaa00998877665544332211", // last valid wins
	}
	for in, want := range cases {
		if got := lastHexToken(in); got != want {
			t.Errorf("lastHexToken(%q)=%q want %q", in, got, want)
		}
	}
}
