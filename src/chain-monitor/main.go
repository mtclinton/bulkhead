// SPDX-License-Identifier: AGPL-3.0-only
//
// bulkhead-chain-monitor — the OFF-BOX audit-chain witness (ADR-0013/0025/0026; closes the
// PRODUCTION-READINESS "continuous off-box monitor" pilot blocker — threat-model.md: the off-box anchor
// "is not yet wired"). bulkhead's three signed, hash-chained audit logs (collector/control/broker) are
// tamper-EVIDENT on-box, but on-box you cannot detect whole-file erasure or a rewound tail — that needs an
// external party that pinned the prior HEAD. This is that party.
//
// Per interval, per device it runs TWO independent halves. ATTESTATION: (1) pulls a FRESH-NONCE quote, (2)
// verifies it with the SAME `bulkhead-collector attest verify` the appliance ships (AK-pinned, expected-D — no
// crypto re-implemented here, so zero drift), reading the three HEADs the quote cryptographically binds
// (ADR-0025). HEAD WITNESS (PRODUCTION-READINESS [73]): EVERY poll, regardless of attestation, it runs
// `bulkhead-collector verify-audit <log> --since=<prior-pinned-HEAD> [--expect-tip=<quoted-HEAD>]` (ADR-0026)
// over each chain — proving the prior-pinned HEAD is still a verified ancestor (no rewind/tail-truncation) and,
// when a fresh quote bound the HEAD, that the log IS the attested one. It then advances the pin to the
// verify-audit-AUTHENTICATED tip (its `tip=` line), so the --since anchor stays inside the ADR-0040 retained
// window (rotation can't prune it before the next check) and a genuine tail-truncation surfaces as REWOUND
// within one interval — even on a box that has STOPPED attesting. OPERATING ASSUMPTION (soundness depends on
// it): the poll interval MUST be shorter than the device's segment-prune cadence (BULKHEAD_AUDIT_SEGMENT_BYTES
// × keep ÷ write-rate), so a pinned HEAD is never pruned between polls. The only time the witness loses its
// anchor is when the device was UNREACHABLE long enough for rotation to prune it across the gap — on-box
// indistinguishable from a truncation, so the monitor FAILS CLOSED (alarms + keeps the last-good anchor) and
// names the dual cause; an operator clears the device state to re-anchor after confirming the gap was benign.
// It durably pins each chain's HEAD
// (trust-on-first-use, like the AK pin) and ALERTS on: a missed attestation (device silent N intervals), a
// quote-verify failure, or a chain rewind/verify-fail/tip-mismatch. The verifier + transport are interfaces so
// the pin/advance/rewind/missed state machine is deterministically unit-tested; the shipped impls shell out to
// bulkhead-collector and ssh.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- config -------------------------------------------------------------------------------------------

type Config struct {
	IntervalSeconds int      `json:"interval_seconds"` // poll cadence
	MissedThreshold int      `json:"missed_threshold"` // consecutive silent polls before a missed-attestation alert
	StateDir        string   `json:"state_dir"`        // durable per-device pins (TOFU anchors) live here
	CollectorBin    string   `json:"collector_bin"`    // path to the relying-party `bulkhead-collector` verifier
	AlertCmd        string   `json:"alert_cmd"`        // optional: `sh -c` run per alert with $BH_ALERT_* in the env
	MetricsOut      string   `json:"metrics_out"`      // optional: write a Prometheus-text exposition here each cycle (atomic)
	Devices         []Device `json:"devices"`
}

type Device struct {
	Name             string  `json:"name"`
	QuoteCmd         string  `json:"quote_cmd"`           // fetch a quote envelope (JSON) to stdout; {nonce} is substituted
	FetchChainCmd    string  `json:"fetch_chain_cmd"`     // fetch a chain log to stdout; {chain} = the chain's remote path
	ListSegmentsCmd  string  `json:"list_segments_cmd"`   // optional ([34]): list retained ADR-0040 sealed-segment paths (one/line) for {chain}; empty => single live file
	ExpectedD        string  `json:"expected_d"`          // expected TCB digest hex; OR set CollectorBinForD to derive it
	CollectorBinForD string  `json:"collector_bin_for_d"` // released collector binary -> `attest expected-d` computes D
	AuditPub         string  `json:"audit_pub"`           // audit pubkey hex or @file for verify-audit (else sibling audit-pub.txt)
	Chains           []Chain `json:"chains"`
}

type Chain struct {
	Domain     string `json:"domain"`      // collector | control | broker (label + pin key)
	RemotePath string `json:"remote_path"` // the chain's path on the device (fetched + named to verify-audit)
	HeadField  string `json:"head_field"`  // which quote field binds this chain: head_{collector,control,broker}_hex
}

// ---- durable state (the TOFU anchors) -----------------------------------------------------------------

type deviceState struct {
	AKPinHex string                `json:"ak_pin_hex"` // trust-on-first-use AK pin (captured on first contact)
	Chains   map[string]chainState `json:"chains"`     // domain -> last verified-and-attested HEAD
	LastOK   int64                 `json:"last_ok_unix"`
	Misses   int                   `json:"misses"`
	Metrics  *pollMetrics          `json:"-"` // transient: this cycle's derived metrics (never persisted)
}

// pollMetrics is the OBSERVABILITY surface derived from a poll — read-only, from the tamper-evident chains +
// the attestation, NOT from any service self-report (a compromised service could lie; the signed chain can't).
// Closes the "no operational metrics" gap without adding any attack surface to the TCB.
type pollMetrics struct {
	Reachable int // 1 if the device produced a quote this cycle
	AttestOK  int // 1 if that quote verified (AK-pinned, expected-D, PCR-14)
	Chains    map[string]chainMetric
}

type chainMetric struct {
	Records   int // record count of the fetched chain log
	Witnessed int // 1 if the HEAD was ingested + verify-audit run this cycle (independent of attestation, [73])
	VerifyOK  int // 1 if verify-audit (--since/--expect-tip) passed this cycle
}

type chainState struct {
	PinnedHead       string `json:"pinned_head_hex"`
	LastUpdate       int64  `json:"last_update_unix"`
	ConsecutiveRaces int    `json:"consecutive_races,omitempty"` // [34]: segment set churned this many polls in a row (evasion guard)
}

// maxConsecutiveRaces: after this many consecutive polls where a rotation raced the segment fetch, ALARM —
// a box that re-rotates every single poll is pathological or evading the witness (perpetually dodging a
// consistent snapshot), not legitimately busy. maxChainFileBytes bounds a single fetched chain file so a
// hostile box cannot OOM the monitor with a giant "segment" (a real chain file is (segKeep+1)×segment-bytes).
const maxConsecutiveRaces = 3

var maxChainFileBytes int64 = 128 << 20 // 128 MiB; var so tests can lower it

func stateFile(dir, dev string) string { return filepath.Join(dir, "device-"+sanitize(dev)+".json") }

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

func loadState(dir, dev string) *deviceState {
	st := &deviceState{Chains: map[string]chainState{}}
	b, err := os.ReadFile(stateFile(dir, dev))
	if err == nil {
		_ = json.Unmarshal(b, st)
		if st.Chains == nil {
			st.Chains = map[string]chainState{}
		}
	}
	return st
}

func saveState(dir, dev string, st *deviceState) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	tmp := stateFile(dir, dev) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, stateFile(dir, dev)) // atomic: never leave a half-written anchor
}

// ---- alerts -------------------------------------------------------------------------------------------

type Alert struct {
	Device string
	Kind   string // missed-attestation | quote-verify-failed | chain-rewind-or-fail | fetch-failed | chain-fetch-unstable
	Domain string // chain domain, when applicable
	Detail string
}

func (a Alert) String() string {
	d := a.Kind
	if a.Domain != "" {
		d += " [" + a.Domain + "]"
	}
	return fmt.Sprintf("ALERT device=%s %s: %s", a.Device, d, a.Detail)
}

// ---- verifier (the crypto engine; real impl shells out to bulkhead-collector) -------------------------

type Verifier interface {
	AKPub(envPath string) (pinHex string, err error)                                                 // attest akpub -> TOFU pin
	ExpectedD(collectorBin string) (dHex string, err error)                                          // attest expected-d <bin>
	VerifyQuote(envPath, expectedD, nonceHex, akPinHex string) error                                 // attest verify (5 checks); err => fail
	VerifyChain(chainPath, auditPub, domain, sinceHead, expectTip string) (tipHex string, err error) // verify-audit --since --expect-tip; returns the authenticated tip
}

type collectorVerifier struct{ bin string }

func (c collectorVerifier) run(args ...string) (string, error) {
	out, err := exec.Command(c.bin, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", c.bin, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (c collectorVerifier) AKPub(envPath string) (string, error) {
	out, err := c.run("attest", "akpub", envPath)
	return strings.TrimSpace(lastHexToken(out)), err
}

func (c collectorVerifier) ExpectedD(collectorBin string) (string, error) {
	out, err := c.run("attest", "expected-d", collectorBin)
	return strings.TrimSpace(lastHexToken(out)), err
}

func (c collectorVerifier) VerifyQuote(envPath, expectedD, nonceHex, akPinHex string) error {
	_, err := c.run("attest", "verify", envPath, expectedD, nonceHex, akPinHex)
	return err
}

func (c collectorVerifier) VerifyChain(chainPath, auditPub, domain, sinceHead, expectTip string) (string, error) {
	args := []string{"verify-audit", chainPath}
	if auditPub != "" {
		args = append(args, auditPub)
	}
	if sinceHead != "" {
		args = append(args, "--since="+sinceHead)
	}
	if expectTip != "" {
		args = append(args, "--expect-tip="+expectTip)
	}
	cmd := exec.Command(c.bin, args...)
	// Make the chain domain EXPLICIT rather than letting verify-audit infer it from our generic temp path —
	// the domain is bound into the signed record encoding, so a wrong guess fails every signature. chainDomain
	// honors BULKHEAD_AUDIT_DOMAIN first.
	if domain != "" {
		cmd.Env = append(os.Environ(), "BULKHEAD_AUDIT_DOMAIN="+domain)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("verify-audit %s: %w: %s", chainPath, err, strings.TrimSpace(string(out)))
	}
	// verify-audit prints "... tip=<64hex>" on its OK line. The tip is the hash of the LAST record the tool
	// just verified (sig/hash/seq/prev), so the off-box witness pins it as an AUTHENTICATED HEAD without
	// re-implementing any chain crypto ([73]). A pass with no parseable tip is itself a (format) failure.
	tip := tipFromVerifyOutput(string(out))
	if tip == "" {
		return "", fmt.Errorf("verify-audit %s: passed but emitted no tip= HEAD: %s", chainPath, strings.TrimSpace(string(out)))
	}
	return tip, nil
}

// tipFromVerifyOutput extracts the authenticated tip HEAD from a successful verify-audit run, whose OK line is
// `verify-audit: OK — N record(s) verified ... tip=<64hex>` (collector verify.go). Returns "" if absent/malformed.
func tipFromVerifyOutput(s string) string {
	for _, f := range strings.Fields(s) {
		if v := strings.TrimPrefix(f, "tip="); v != f {
			v = strings.ToLower(strings.TrimSpace(v))
			if len(v) == 64 && isHex(v) {
				return v
			}
		}
	}
	return ""
}

// lastHexToken returns the last whitespace-token that looks like a hex blob (the tools print a hex result,
// sometimes after a human label like "OK <hex>" or "D=<hex>").
func lastHexToken(s string) string {
	best := ""
	for _, f := range strings.Fields(s) {
		f = strings.TrimPrefix(f, "D=")
		if len(f) >= 32 && isHex(f) {
			best = f
		}
	}
	return best
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil && len(s)%2 == 0
}

// ---- transport (fetch quote/log; real impl runs the configured shell command) -------------------------

type Transport interface {
	Fetch(cmdTemplate string, subs map[string]string) ([]byte, error)
}

type shellTransport struct{}

func (shellTransport) Fetch(cmdTemplate string, subs map[string]string) ([]byte, error) {
	cmd := cmdTemplate
	for k, v := range subs {
		cmd = strings.ReplaceAll(cmd, "{"+k+"}", v)
	}
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return nil, fmt.Errorf("fetch %q: %w", cmd, err)
	}
	return out, nil
}

// ---- the per-device poll (the state machine under test) -----------------------------------------------

// quoteEnvelope is the subset of the attest envelope we read for the bound HEADs. The crypto verification
// of the envelope itself is delegated to `attest verify` (Verifier.VerifyQuote) — we only PARSE it after
// that call succeeds, so these fields are already proven non-repudiable.
type quoteEnvelope struct {
	HeadCollector string `json:"head_collector_hex"`
	HeadControl   string `json:"head_control_hex"`
	HeadBroker    string `json:"head_broker_hex"`
}

func (e quoteEnvelope) head(field string) string {
	switch field {
	case "head_collector_hex":
		return e.HeadCollector
	case "head_control_hex":
		return e.HeadControl
	case "head_broker_hex":
		return e.HeadBroker
	}
	return ""
}

// pollDevice runs one poll cycle for one device. It mutates st and returns any alerts. Deterministic given
// its injected verifier/transport/nonce/now — no global clock or RNG inside (that is the caller's job). It is
// TWO independent halves: the attestation poll (the quote), and the off-box HEAD witness over the chains. The
// witness runs EVERY poll regardless of attestation, so a box that stops attesting but still serves a
// TRUNCATED chain is still caught within one interval (PRODUCTION-READINESS [73]).
func pollDevice(cfg *Config, dev *Device, st *deviceState, v Verifier, tr Transport, nonce string, now int64, workDir string) []Alert {
	st.Metrics = &pollMetrics{Chains: map[string]chainMetric{}}
	quoteOK, reachable, env, alerts := attestPoll(cfg, dev, st, v, tr, nonce, now, workDir)
	alerts = append(alerts, witnessChains(dev, st, v, tr, now, workDir, quoteOK, reachable, env)...)
	return alerts
}

// attestPoll is the attestation half of a poll: fetch + TOFU-AK + verify a fresh-nonce quote. It mutates
// st.Misses/LastOK/AKPinHex/Metrics and returns whether the quote verified (=> env carries the attested
// HEADs, the strongest --expect-tip binding), whether the box answered at all (reachable), the parsed env,
// and any attestation alerts. It deliberately does NOT short-circuit the caller's chain witness — a failed or
// absent attestation must still let the HEAD witness run ([73]).
func attestPoll(cfg *Config, dev *Device, st *deviceState, v Verifier, tr Transport, nonce string, now int64, workDir string) (quoteOK, reachable bool, env quoteEnvelope, alerts []Alert) {
	// (1) fetch a fresh-nonce quote. A silent/erroring device is a candidate missed-attestation.
	envBytes, err := tr.Fetch(dev.QuoteCmd, map[string]string{"nonce": nonce})
	if err != nil || len(envBytes) == 0 {
		st.Misses++
		if st.Misses >= cfg.MissedThreshold {
			detail := fmt.Sprintf("no quote for %d consecutive polls", st.Misses)
			if err != nil {
				detail += ": " + err.Error()
			}
			alerts = append(alerts, Alert{Device: dev.Name, Kind: "missed-attestation", Detail: detail})
		}
		return false, false, env, alerts
	}
	st.Metrics.Reachable = 1

	envPath := filepath.Join(workDir, "env.json")
	if werr := os.WriteFile(envPath, envBytes, 0o600); werr != nil {
		alerts = append(alerts, Alert{Device: dev.Name, Kind: "fetch-failed", Detail: "cannot stage envelope: " + werr.Error()})
		return false, true, env, alerts
	}

	// (2) trust-on-first-use: capture the AK pin out of the first envelope. (Operator must cross-check this
	// pin out-of-band; a device compromised AT first contact would pin a bad AK — inherent to TOFU.)
	if st.AKPinHex == "" {
		pin, perr := v.AKPub(envPath)
		if perr != nil || pin == "" {
			st.Misses++
			alerts = append(alerts, Alert{Device: dev.Name, Kind: "quote-verify-failed", Detail: "AK pin capture failed: " + errStr(perr)})
			return false, true, env, alerts
		}
		st.AKPinHex = pin
		fmt.Printf("NOTICE device=%s TOFU AK pin captured: %s (cross-check out-of-band)\n", dev.Name, short(pin))
	}

	// (3) verify the quote: AK-pinned, fresh-nonce, expected-D, PCR 14. This proves the bound HEADs are
	// non-repudiable + the box is in the expected armed posture.
	expectedD := dev.ExpectedD
	if expectedD == "" && dev.CollectorBinForD != "" {
		if d, derr := v.ExpectedD(dev.CollectorBinForD); derr == nil {
			expectedD = d
		} else {
			alerts = append(alerts, Alert{Device: dev.Name, Kind: "quote-verify-failed", Detail: "expected-D derivation failed: " + derr.Error()})
			return false, true, env, alerts
		}
	}
	if qerr := v.VerifyQuote(envPath, expectedD, nonce, st.AKPinHex); qerr != nil {
		st.Misses++ // a box that can't produce a verifiable quote is as bad as a silent one
		alerts = append(alerts, Alert{Device: dev.Name, Kind: "quote-verify-failed", Detail: qerr.Error()})
		return false, true, env, alerts
	}

	_ = json.Unmarshal(envBytes, &env)
	// quote verified -> the device is live + attesting. Reset the miss counter regardless of chain outcomes.
	st.Misses = 0
	st.LastOK = now
	st.Metrics.AttestOK = 1
	return true, true, env, alerts
}

// witnessChains is the OFF-BOX HEAD WITNESS (PRODUCTION-READINESS [73]). It runs EVERY poll, independent of
// attestation: for each chain it fetches the log and runs verify-audit with --since=<prior-pinned HEAD> (the
// no-rewind anchor) and, when a fresh quote verified this cycle, --expect-tip=<attested HEAD> (the strongest
// binding). It advances the pin to the verify-audit-AUTHENTICATED tip on success, so the --since anchor stays
// within the retained window and ADR-0040 rotation can never prune it out from under us (operators size the
// poll interval below the segment-prune cadence). A genuine TAIL-TRUNCATION makes the last-pinned HEAD vanish
// from the chain => verify-audit returns REWOUND within one interval; a clean chain advances the pin. The pin
// only ratchets FORWARD (advance only on a full PASS), so a rewind keeps the last-good anchor for the next poll.
func witnessChains(dev *Device, st *deviceState, v Verifier, tr Transport, now int64, workDir string, quoteOK, reachable bool, env quoteEnvelope) []Alert {
	var alerts []Alert
	for _, ch := range dev.Chains {
		// Reconstruct the chain off-box into a per-domain dir, mirroring the ADR-0040 segment layout so a
		// ROTATED chain verifies as one continuous chain ([34]). RemoveAll first so a pruned segment from a
		// prior poll never lingers and gets verified as still-present.
		destDir := filepath.Join(workDir, sanitize(ch.Domain))
		_ = os.RemoveAll(destDir)
		if werr := os.MkdirAll(destDir, 0o700); werr != nil {
			alerts = append(alerts, Alert{Device: dev.Name, Kind: "fetch-failed", Domain: ch.Domain, Detail: werr.Error()})
			continue
		}
		logPath, records, raced, ferr := fetchChainToDir(tr, dev, ch, destDir)
		if ferr != nil {
			// Flag a chain-fetch failure only when the box otherwise answered (reachable): a fully silent box
			// is already covered by missed-attestation, so do not double-alarm every chain every poll.
			if reachable {
				alerts = append(alerts, Alert{Device: dev.Name, Kind: "fetch-failed", Domain: ch.Domain, Detail: ferr.Error()})
			}
			continue
		}
		if raced {
			// A rotation sealed/pruned a segment WHILE we were fetching the multi-file chain — the off-box
			// snapshot is inconsistent (usually not an attack). Skip the verdict this poll (no advance); the next
			// poll re-checks the now-stable chain. But a box that re-rotates EVERY poll would perpetually dodge a
			// consistent snapshot and never be verified — so after maxConsecutiveRaces in a row we ALARM (the
			// witness must not be silently evadable).
			cs := st.Chains[ch.Domain]
			cs.ConsecutiveRaces++
			st.Chains[ch.Domain] = cs
			if cs.ConsecutiveRaces >= maxConsecutiveRaces {
				alerts = append(alerts, Alert{Device: dev.Name, Kind: "chain-fetch-unstable", Domain: ch.Domain,
					Detail: fmt.Sprintf("the segment set changed on %d consecutive polls — pathological rotation or an evasion attempt (a box re-rotating every poll to dodge the off-box witness); investigate the device", cs.ConsecutiveRaces)})
			} else {
				fmt.Printf("NOTICE device=%s chain=%s: segment rotation raced the fetch; skipping the verdict this poll (%d consecutive)\n", dev.Name, ch.Domain, cs.ConsecutiveRaces)
			}
			continue
		}
		// A consistent snapshot — clear any prior race streak (kept here so a rewind, which does not rewrite
		// the pin below, still resets the counter).
		if cs := st.Chains[ch.Domain]; cs.ConsecutiveRaces != 0 {
			cs.ConsecutiveRaces = 0
			st.Chains[ch.Domain] = cs
		}
		// The strongest binding (the cryptographically-attested HEAD) is used ONLY when a fresh quote verified
		// this cycle; otherwise the chain is witnessed via --since alone (which still catches a tail-truncation
		// of any previously-observed HEAD — the [73] gap a quote-gated check left open). A verified quote that
		// binds no HEAD for this chain (env.head == "") is NOT an error — it just means no --expect-tip this
		// cycle, so we witness via --since exactly as on an unattested poll.
		expectTip := ""
		if quoteOK {
			expectTip = env.head(ch.HeadField)
		}
		prior := st.Chains[ch.Domain].PinnedHead // "" on first observation => no --since anchor yet
		tip, cerr := v.VerifyChain(logPath, dev.AuditPub, ch.Domain, prior, expectTip)
		if cerr != nil {
			// verify-audit fails closed on: bad signature/hash, a deleted interior record, tip != the attested
			// HEAD, or the prior-pinned HEAD not being a verified ancestor (REWOUND). Under the operating
			// assumption (poll interval < the ADR-0040 segment-prune cadence) the prior pin is ALWAYS still in
			// the retained window, so a REWOUND verdict is a genuine tail-truncation of a previously-witnessed
			// HEAD. The one benign way to reach it is if the device was UNREACHABLE long enough for rotation to
			// prune the anchor (the witness could not advance the pin across the gap) — indistinguishable on-box
			// from a truncation, so we FAIL CLOSED (alarm + keep the last-good anchor) and label the dual cause
			// for the operator. Witnessed=1 (we DID ingest the HEAD this cycle), VerifyOK=0.
			st.Metrics.Chains[ch.Domain] = chainMetric{Records: records, Witnessed: 1, VerifyOK: 0}
			detail := cerr.Error()
			if prior != "" {
				detail += " — the prior-pinned HEAD is gone: a tail-truncation/rewind, OR (only if the device was unreachable past the ADR-0040 prune cadence) a benign rotation that pruned the anchor; correlate with this device's reachability/missed-attestation. After confirming the device is healthy, clear its monitor state file to re-anchor."
			}
			alerts = append(alerts, Alert{Device: dev.Name, Kind: "chain-rewind-or-fail", Domain: ch.Domain, Detail: detail})
			continue // do NOT advance the pin — keep the last-good anchor
		}
		st.Metrics.Chains[ch.Domain] = chainMetric{Records: records, Witnessed: 1, VerifyOK: 1}
		// Advance the pin to the verify-audit-authenticated tip (works with OR without a quote), so next poll's
		// --since anchor is recent and rotation can't prune it before we re-check.
		st.Chains[ch.Domain] = chainState{PinnedHead: tip, LastUpdate: now}
	}
	return alerts
}

// fetchChainToDir fetches a chain off-box into destDir, mirroring the on-box ADR-0040 segment layout so
// verify-audit reconstructs a ROTATED chain ([34]): the live file as <base> plus each retained sealed segment
// as <base>.NNNNNN (the "%s.%06d" contract). When the device exposes no ListSegmentsCmd the chain is treated
// as a single live file (backward compatible). To stop a rotation from racing the multi-file fetch, the
// segment set is read BEFORE and AFTER the fetches; if it changed mid-fetch the snapshot is inconsistent and
// the caller skips the verdict (raced=true). Returns the live-file path, the total record count across all
// fetched files, raced, and the first error.
func fetchChainToDir(tr Transport, dev *Device, ch Chain, destDir string) (logPath string, records int, raced bool, err error) {
	base := filepath.Base(ch.RemotePath)
	logPath = filepath.Join(destDir, base)

	segs1, err := listRemoteSegments(tr, dev, ch)
	if err != nil {
		return logPath, 0, false, err
	}
	for _, seg := range segs1 {
		n, ferr := fetchOneInto(tr, dev, seg, filepath.Join(destDir, filepath.Base(seg)))
		if ferr != nil {
			return logPath, 0, false, ferr
		}
		records += n
	}
	n, ferr := fetchOneInto(tr, dev, ch.RemotePath, logPath)
	if ferr != nil {
		return logPath, 0, false, ferr
	}
	records += n

	if dev.ListSegmentsCmd != "" {
		segs2, lerr := listRemoteSegments(tr, dev, ch)
		if lerr != nil {
			return logPath, 0, false, lerr
		}
		if !sameStrings(segs1, segs2) {
			return logPath, records, true, nil
		}
	}
	return logPath, records, false, nil
}

// listRemoteSegments runs the device's ListSegmentsCmd and returns the retained sealed-segment paths it names,
// keeping only valid <base>.<all-digits> siblings (mirrors the collector's listSegments filter so audit-pub.txt,
// *.tmp, or another chain's files in a shared dir are excluded) in ASCENDING segment order. No command
// configured => no segments (a never-rotated / single-file chain).
func listRemoteSegments(tr Transport, dev *Device, ch Chain) ([]string, error) {
	if dev.ListSegmentsCmd == "" {
		return nil, nil
	}
	out, err := tr.Fetch(dev.ListSegmentsCmd, map[string]string{"chain": ch.RemotePath})
	if err != nil {
		return nil, err
	}
	prefix := filepath.Base(ch.RemotePath) + "."
	type seg struct {
		path string
		n    uint64
	}
	var segs []seg
	seen := map[uint64]bool{}
	for _, ln := range strings.Split(string(out), "\n") {
		p := strings.TrimSpace(ln)
		if p == "" {
			continue
		}
		name := filepath.Base(p)
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suf := name[len(prefix):]
		if suf == "" || strings.TrimLeft(suf, "0123456789") != "" {
			continue // not an all-digit suffix
		}
		num, perr := strconv.ParseUint(suf, 10, 64)
		if perr != nil {
			continue
		}
		// On-box a segment number is one inode. A list that names the SAME number twice (e.g. two paths whose
		// basename collides — `<base>.000001` from two dirs) would overwrite one fetch with the other; reject it
		// rather than silently pick one (a hostile box must not choose which signed segment we verify).
		if seen[num] {
			return nil, fmt.Errorf("segment %06d listed more than once by ListSegmentsCmd", num)
		}
		seen[num] = true
		segs = append(segs, seg{p, num})
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].n < segs[j].n })
	paths := make([]string, len(segs))
	for i, s := range segs {
		paths[i] = s.path
	}
	return paths, nil
}

// fetchOneInto fetches one remote file via FetchChainCmd and writes it to dest, returning its record count.
func fetchOneInto(tr Transport, dev *Device, remotePath, dest string) (int, error) {
	b, err := tr.Fetch(dev.FetchChainCmd, map[string]string{"chain": remotePath})
	if err != nil {
		return 0, err
	}
	if int64(len(b)) > maxChainFileBytes {
		// A hostile box must not be able to OOM the monitor with a giant "chain file" — a real one is bounded
		// by (segKeep+1)×BULKHEAD_AUDIT_SEGMENT_BYTES (≈16 MiB at the defaults).
		return 0, fmt.Errorf("chain file %s is %d bytes (> the %d-byte cap)", remotePath, len(b), maxChainFileBytes)
	}
	if err := os.WriteFile(dest, b, 0o600); err != nil {
		return 0, err
	}
	records := 0
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) != "" {
			records++
		}
	}
	return records, nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func errStr(e error) string {
	if e == nil {
		return "(nil)"
	}
	return e.Error()
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	return h
}

// ---- driver -------------------------------------------------------------------------------------------

func nonceHex() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// runOnce polls every device once, persists state, emits alerts, and returns the alert count.
func runOnce(cfg *Config, v Verifier, tr Transport) int {
	total := 0
	names := make([]string, len(cfg.Devices))
	for i := range cfg.Devices {
		names[i] = cfg.Devices[i].Name
	}
	sort.Strings(names)
	byName := map[string]*Device{}
	for i := range cfg.Devices {
		byName[cfg.Devices[i].Name] = &cfg.Devices[i]
	}
	collected := map[string]*deviceState{}
	for _, name := range names {
		dev := byName[name]
		st := loadState(cfg.StateDir, dev.Name)
		work, _ := os.MkdirTemp("", "bh-chain-mon-")
		alerts := pollDevice(cfg, dev, st, v, tr, nonceHex(), time.Now().Unix(), work)
		os.RemoveAll(work)
		collected[name] = st
		if err := saveState(cfg.StateDir, dev.Name, st); err != nil {
			fmt.Fprintf(os.Stderr, "WARN device=%s state save failed: %v\n", dev.Name, err)
		}
		for _, a := range alerts {
			fmt.Println(a.String())
			fireAlertCmd(cfg.AlertCmd, a)
			total++
		}
		if len(alerts) == 0 {
			if st.Misses > 0 {
				// a silent poll BELOW the missed threshold is not an alert yet, but it is NOT "continuous" —
				// say so honestly rather than printing OK on a box we could not reach.
				fmt.Printf("WARN device=%s silent poll %d/%d (no verifiable quote this cycle)\n", dev.Name, st.Misses, cfg.MissedThreshold)
			} else {
				fmt.Printf("OK device=%s attested + %d chains continuous\n", dev.Name, len(dev.Chains))
			}
		}
	}
	if cfg.MetricsOut != "" {
		if err := writeMetrics(cfg.MetricsOut, collected, time.Now().Unix()); err != nil {
			fmt.Fprintf(os.Stderr, "WARN metrics write failed: %v\n", err)
		}
	}
	return total
}

// renderMetrics emits a Prometheus-text exposition derived from this cycle's per-device state — read-only,
// from the tamper-evident chains + the attestation, so it scrapes cleanly into a dashboard/alert pipeline
// (e.g. a node-exporter textfile collector) over the management plane without touching the appliance.
func renderMetrics(states map[string]*deviceState, now int64) string {
	var b strings.Builder
	b.WriteString("# HELP bulkhead_device_reachable Device produced an attestation quote this cycle (1) or not (0).\n# TYPE bulkhead_device_reachable gauge\n")
	b.WriteString("# HELP bulkhead_attestation_ok The fresh-nonce quote verified (AK-pinned, expected-D, PCR-14).\n# TYPE bulkhead_attestation_ok gauge\n")
	b.WriteString("# HELP bulkhead_device_missed_polls Consecutive polls with no verifiable quote.\n# TYPE bulkhead_device_missed_polls gauge\n")
	b.WriteString("# HELP bulkhead_chain_records Record count of the fetched audit chain this cycle.\n# TYPE bulkhead_chain_records gauge\n")
	b.WriteString("# HELP bulkhead_chain_witnessed The chain HEAD was ingested + verify-audit run this cycle (1), independent of attestation.\n# TYPE bulkhead_chain_witnessed gauge\n")
	b.WriteString("# HELP bulkhead_chain_verify_ok verify-audit (--since/--expect-tip) passed for the chain (1) or failed/rewound (0).\n# TYPE bulkhead_chain_verify_ok gauge\n")
	names := make([]string, 0, len(states))
	for n := range states {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		st := states[name]
		reach, attest := 0, 0
		if st.Metrics != nil {
			reach, attest = st.Metrics.Reachable, st.Metrics.AttestOK
		}
		fmt.Fprintf(&b, "bulkhead_device_reachable{device=%q} %d\n", name, reach)
		fmt.Fprintf(&b, "bulkhead_attestation_ok{device=%q} %d\n", name, attest)
		fmt.Fprintf(&b, "bulkhead_device_missed_polls{device=%q} %d\n", name, st.Misses)
		if st.Metrics != nil {
			doms := make([]string, 0, len(st.Metrics.Chains))
			for d := range st.Metrics.Chains {
				doms = append(doms, d)
			}
			sort.Strings(doms)
			for _, d := range doms {
				cm := st.Metrics.Chains[d]
				fmt.Fprintf(&b, "bulkhead_chain_records{device=%q,chain=%q} %d\n", name, d, cm.Records)
				fmt.Fprintf(&b, "bulkhead_chain_witnessed{device=%q,chain=%q} %d\n", name, d, cm.Witnessed)
				fmt.Fprintf(&b, "bulkhead_chain_verify_ok{device=%q,chain=%q} %d\n", name, d, cm.VerifyOK)
			}
		}
	}
	fmt.Fprintf(&b, "bulkhead_monitor_last_run_unixtime %d\n", now)
	return b.String()
}

func writeMetrics(path string, states map[string]*deviceState, now int64) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(renderMetrics(states, now)), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path) // atomic: a scraper never reads a half-written exposition
}

func fireAlertCmd(cmd string, a Alert) {
	if cmd == "" {
		return
	}
	c := exec.Command("sh", "-c", cmd)
	c.Env = append(os.Environ(),
		"BH_ALERT_DEVICE="+a.Device, "BH_ALERT_KIND="+a.Kind,
		"BH_ALERT_DOMAIN="+a.Domain, "BH_ALERT_DETAIL="+a.Detail)
	_ = c.Run()
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.IntervalSeconds <= 0 {
		cfg.IntervalSeconds = 300
	}
	if cfg.MissedThreshold <= 0 {
		cfg.MissedThreshold = 2
	}
	if cfg.StateDir == "" {
		cfg.StateDir = "/var/lib/bulkhead-chain-monitor"
	}
	if cfg.CollectorBin == "" {
		cfg.CollectorBin = "bulkhead-collector"
	}
	if len(cfg.Devices) == 0 {
		return nil, fmt.Errorf("%s: no devices configured", path)
	}
	return &cfg, nil
}

func main() {
	cfgPath := flag.String("config", "/etc/bulkhead/chain-monitor.json", "config file")
	once := flag.Bool("once", false, "poll every device once and exit (exit 1 if any alert fired)")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "chain-monitor:", err)
		os.Exit(2)
	}
	v := collectorVerifier{bin: cfg.CollectorBin}
	tr := shellTransport{}

	if *once {
		if runOnce(cfg, v, tr) > 0 {
			os.Exit(1) // any alert -> nonzero, so `--once` is usable as a check/cron gate
		}
		return
	}
	fmt.Printf("chain-monitor: %d devices, every %ds, state %s\n", len(cfg.Devices), cfg.IntervalSeconds, cfg.StateDir)
	for {
		runOnce(cfg, v, tr)
		time.Sleep(time.Duration(cfg.IntervalSeconds) * time.Second)
	}
}
