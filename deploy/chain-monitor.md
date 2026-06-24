<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Off-box audit-chain monitor

`bulkhead-chain-monitor` is the external witness for bulkhead's three signed audit chains
(collector / control / broker). The chains are tamper-**evident** on the appliance, but on-box you
cannot detect whole-file erasure or a silently-rewound tail — that requires a party that pinned the
prior HEAD off the box. This is that party (closes the `docs/PRODUCTION-READINESS.md` "continuous
off-box monitor" pilot blocker; `docs/threat-model.md` notes the off-box anchor was "not yet wired").

It runs on the operator's **management host**, NOT on the appliance, and reaches each device over the
tailnet (SSH-as-uid-0 is the documented transport).

## What it does, each interval, per device

1. Pulls a **fresh-nonce** attestation quote (`bulkhead-collector attest quote <nonce>`).
2. Verifies it with the **same** verifier the appliance ships — `bulkhead-collector attest verify`
   (AK-pinned, expected-D, PCR 14). No crypto is re-implemented in the monitor, so there is zero drift.
3. Reads the three chain HEADs the quote cryptographically binds (ADR-0025).
4. For each chain — **every poll, whether or not the quote verified** (PRODUCTION-READINESS [73]) — runs
   `bulkhead-collector verify-audit <log> --since=<prior-pinned-HEAD> [--expect-tip=<quoted-HEAD>]`
   (ADR-0026). The `--since` no-rewind check proves the prior-pinned HEAD is still a verified ancestor (no
   rewind / fork / tail-truncation); `--expect-tip` is added **only when a fresh quote bound the HEAD**, tying
   the verified log to the attestation. On success the pin is advanced to the verify-audit-**authenticated**
   tip (its `tip=` line). Because the chain is witnessed independent of attestation, a box that **stops
   attesting** but serves a withheld/truncated tail is still caught within one interval.
5. **Alerts** on: a missed attestation (silent ≥ `missed_threshold` polls), a quote-verify failure,
   or a chain rewind / verify-fail / tip-mismatch. A rewound chain does **not** advance the pin (the
   last-good anchor is kept). Alerts go to stdout and, if `alert_cmd` is set, to that command with
   `$BH_ALERT_{DEVICE,KIND,DOMAIN,DETAIL}` in the environment.

> **OPERATING ASSUMPTION — set the poll interval below the device's segment-prune cadence.** The witness's
> soundness rests on the prior-pinned HEAD always still being in the ADR-0040 retained window at the next
> poll (the monitor re-pins to the current tip each cycle). If a device is **unreachable** long enough for
> rotation to prune the anchor across the gap, the recovered chain yields a `REWOUND` verdict that is on-box
> **indistinguishable** from a real tail-truncation — so the monitor **fails closed** (alarms + keeps the
> last-good anchor) and the `chain-rewind-or-fail` detail names the dual cause (truncation **or** a benign
> rotation gap; correlate with the device's reachability/missed-attestation). After confirming the gap was
> benign, **clear the device's state file** to re-anchor. Size `interval_seconds` so a healthy device is
> polled several times per `BULKHEAD_AUDIT_SEGMENT_BYTES`-worth of writes.

The per-device AK pin and per-chain HEADs are **trust-on-first-use** and persisted under `state_dir`
(atomic writes). **Cross-check the TOFU AK pin out-of-band** on first enrollment — a device already
compromised at first contact would pin a bad AK (inherent to TOFU). The `-enroll` step makes this explicit.

## Build & run

```sh
cd src/chain-monitor && CGO_ENABLED=0 go build -o /usr/local/bin/bulkhead-chain-monitor .
# bulkhead-collector (the verifier) must also be on the management host (built from the same release).

# 1. ENROLL (first contact): capture + display each device's TOFU anchors, then CROSS-CHECK the AK pin
#    out-of-band against the device's known attestation key before trusting any later run.
bulkhead-chain-monitor -config /etc/bulkhead/chain-monitor.json -enroll
# 2. then run continuously (or as a cron/check gate):
bulkhead-chain-monitor -config /etc/bulkhead/chain-monitor.json            # daemon: loop every interval_seconds
bulkhead-chain-monitor -config /etc/bulkhead/chain-monitor.json -once      # one sweep; exit 1 if any alert (cron/check gate)
```

`-enroll` does one poll per device and prints the captured **AK pin** + each chain's pinned **HEAD**, exiting
non-zero if any device could not be reached/verified. An already-enrolled device is reported, not re-pinned
(to re-enroll, delete its state file). This is the moment to defeat TOFU's one weakness — confirm the AK pin is
the device's real attestation key (e.g. read it from the box over a separate trusted channel) before the
daemon starts trusting it.

**Managed deployment:** run it as an always-on systemd service on the management host with the hardened unit
template `deploy/bulkhead-chain-monitor.service` (daemon mode; `StateDirectory=` holds the TOFU pins, least-
privilege sandbox, restart-on-failure). The unit's header has the install steps. For a cron/check-gate style
instead, point a `.timer` at the `-once` form (it exits non-zero on any alert). See
`deploy/chain-monitor.example.json` for the config shape.

## Metrics / observability

Set `metrics_out` to a file path and each cycle the monitor writes a Prometheus-text exposition there
(atomic rename), derived **read-only** from the tamper-evident chains + the attestation — so it closes the
"no operational metrics" gap without adding any attack surface to the appliance (a compromised service could
lie about its own metrics; the signed chain cannot). Point a node-exporter textfile collector (or any
scraper) at it. Series: `bulkhead_device_reachable` / `bulkhead_attestation_ok` /
`bulkhead_device_missed_polls` (per device) and `bulkhead_chain_records` / `bulkhead_chain_witnessed`
(the HEAD was ingested + verify-audit run this cycle, independent of attestation) / `bulkhead_chain_verify_ok`
(per device+chain), plus `bulkhead_monitor_last_run_unixtime`.

## Limitations / follow-ups

- **Segmented (rotated) chains (ADR-0040):** SUPPORTED. Set `list_segments_cmd` (lists the retained
  `<base>.NNNNNN` sealed-segment paths for `{chain}`, one per line — see the example config). Each poll the
  monitor fetches every retained segment + the live file, mirrors the on-box `<base>.NNNNNN` layout into a
  per-domain temp dir, and `verify-audit` reconstructs the rotated chain as one continuous chain. To stop a
  rotation from racing the multi-file fetch, the segment set is read before AND after the fetches; if it
  changed the snapshot is inconsistent and that chain's verdict is skipped for one poll (no alarm). With no
  `list_segments_cmd` the chain is treated as a single live file (correct for never-rotated chains, but it
  will false-alarm once that chain rotates — set the command). Note the `--since` anchor must still be in the
  retained window, which the [operating assumption](#what-it-does-each-interval-per-device) guarantees.
- **Transport:** any command that emits the quote / log to stdout works (`ssh`, a serial bridge, a
  local `cat` of captured artifacts). `{nonce}` and `{chain}` are substituted into the templates.
