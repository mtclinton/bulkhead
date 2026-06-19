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
4. For each chain, runs `bulkhead-collector verify-audit <log> --since=<prior-pinned-HEAD>
   --expect-tip=<quoted-HEAD>` (ADR-0026). This proves the shipped log **is** the attested one
   (`--expect-tip`) and that the prior-pinned HEAD is still a verified ancestor (`--since` ⇒ no
   rewind / fork / truncated tail), then advances the pin.
5. **Alerts** on: a missed attestation (silent ≥ `missed_threshold` polls), a quote-verify failure,
   or a chain rewind / verify-fail / tip-mismatch. A rewound chain does **not** advance the pin (the
   last-good anchor is kept). Alerts go to stdout and, if `alert_cmd` is set, to that command with
   `$BH_ALERT_{DEVICE,KIND,DOMAIN,DETAIL}` in the environment.

The per-device AK pin and per-chain HEADs are **trust-on-first-use** and persisted under `state_dir`
(atomic writes). **Cross-check the TOFU AK pin out-of-band** on first enrollment — a device already
compromised at first contact would pin a bad AK (inherent to TOFU). A captured pin prints a `NOTICE`.

## Build & run

```sh
cd src/chain-monitor && CGO_ENABLED=0 go build -o /usr/local/bin/bulkhead-chain-monitor .
# bulkhead-collector (the verifier) must also be on the management host (built from the same release).
bulkhead-chain-monitor -config /etc/bulkhead/chain-monitor.json            # daemon: loop every interval_seconds
bulkhead-chain-monitor -config /etc/bulkhead/chain-monitor.json -once      # one sweep; exit 1 if any alert (cron/check gate)
```

See `deploy/chain-monitor.example.json` for the config shape.

## Limitations / follow-ups

- **Segmented (rotated) chains (ADR-0040):** the example `fetch_chain_cmd` ships only the live
  `*.jsonl`. Once a chain has rotated, `verify-audit` needs the retained sealed segments
  (`<base>.NNNNNN`) alongside the live file, and a pruned `--since` anchor must have been archived
  off-box *before* the on-box prune. For rotated chains, configure `fetch_chain_cmd` to ship the whole
  chain directory (e.g. `tar -C <dir> -cf - <base>.jsonl <base>.[0-9]*`) and extend the monitor to
  extract it — tracked as a follow-up. Non-rotated chains (early deployments) are fully covered today.
- **Transport:** any command that emits the quote / log to stdout works (`ssh`, a serial bridge, a
  local `cat` of captured artifacts). `{nonce}` and `{chain}` are substituted into the templates.
