<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# bulkhead — Incident Response & Tamper-Evidence Runbook

> Operator runbook. Every step cites a real shipped command, unit, socket, or ADR.
> Where a capability is proposed/partial/bare-metal-pending it is flagged inline.
> Cross-reference: `docs/PRODUCTION-READINESS.md` §1 "operational-day2" (this runbook
> closes the `[ ] Incident-response & tamper-evidence runbook` pilot blocker) and the
> `Known gaps / pending` section at the end.

## Scope & standing assumptions

bulkhead has strong IR **primitives** — signed cross-boot audit chains, an off-box
witness, fail-closed boot gates, surgical containment levers, A/B rollback. This runbook
turns those primitives into playbooks. It does **not** invent capabilities; honest gaps
are flagged.

Three standing assumptions frame everything below:

1. **The off-box monitor is the primary detector.** `bulkhead-chain-monitor`
   (`src/chain-monitor/main.go`) runs on the operator's **management host** (not the
   appliance), reaching each device over the tailnet. Per interval per device it pulls a
   fresh-nonce attestation quote, verifies it with the shipped `bulkhead-collector attest
   verify` (AK-pinned, expected-D, PCR-14), reads the three quote-bound chain HEADs, and
   runs `verify-audit --since=<prior-pinned-HEAD> --expect-tip=<quoted-HEAD>` per chain
   (main.go:285-335). It is the **only** thing that catches whole-file erasure or a
   silently-rewound tail — the on-box verifier cannot (verify.go:19-31). Its three alert
   kinds (`missed-attestation`, `quote-verify-failed`, `chain-rewind-or-fail`) are the
   primary triggers to start a playbook.

2. **The signed chains are the evidence.** Five Ed25519-signed, SHA-256 hash-chained,
   domain-tagged, cross-boot append-only logs on the persistent `/data` partition
   (`/dev/sda6`, outside the RAUC A/B slots) record every authority delta the box and its
   agents took. PRESERVE these (export logs + a fresh quote) **before** containment so the
   blast radius is captured cryptographically before you perturb it.

3. **Fail-closed is the default.** The boot gate refuses to launch on a tampered chain
   (`bulkhead-verify-audit.service`); an unarmed/dirty posture cannot join the tailnet
   (`bulkhead-attest-gate.service`); a missing sealed seed over surviving chains refuses to
   mint rather than masking history (`bulkhead-seal-audit-key`). The one deliberate
   fail-**safe** exception is enforcement: a failed arm degrades to **observe**, never a
   brick (ADR-0018) — which is why "degraded to observe" is an incident class detectable
   only off-box.

---

## Detection signals

| Signal | How it surfaces (command / alert / log) | What it means | Attacker can / can't hide |
|---|---|---|---|
| **chain-rewind-or-fail** (off-box) | `bulkhead-chain-monitor` alert `ALERT device=<d> chain-rewind-or-fail [<domain>]: …`; `BH_ALERT_KIND=chain-rewind-or-fail`; `--once` exits 1 (main.go:328-334, 451-453) | `verify-audit` failed closed: bad sig/hash, deleted interior record, prior-pinned HEAD no longer a verified ancestor (REWOUND/FORKED), or tip ≠ attested HEAD (withheld/truncated/erased tail) | **Can't hide off-box**: whole-file erasure & tail truncation are caught here and *nowhere else*. **Caveat**: TOFU — a device compromised at first contact pins a bad anchor; a fork strictly *above* the last observation needs a faster poll (ADR-0026 Seam). Monitor does **not** advance the pin on failure — last-good anchor kept. |
| **quote-verify-failed** (off-box) | `bulkhead-chain-monitor` alert `quote-verify-failed: <detail>` (main.go:296-299) | One of the 5 `attest verify` checks failed: AK ≠ pinned AK, magic ≠ TPM_GENERATED, QualifyingData ≠ fresh nonce (replay), bad ECDSA sig, or PCR-14 ≠ `H(SHA256(H(0‖expected-D)))` (ADR-0019). Box is in a different posture (booted observe / map-flipped), replayed an old quote, forged an envelope, or its TPM is wedged | **Can't** forge a quote in the *expected armed posture* once an EK-rooted AK pin is provisioned. **Caveat (shipped default)**: AK pin is TOFU/structural-fallback under qemu/dev — a software-forged quote is rejected only once an EK-rooted pin exists (ADR-0019/0020 Seam). Attests boot/runtime posture, **not** per-agent egress policy and **not** an in-TCB compromise *after* the PCR-14 extend (ADR-0023 "does NOT catch"). |
| **missed-attestation** (off-box) | `bulkhead-chain-monitor` alert `missed-attestation: no quote for N consecutive polls` once `Misses ≥ missed_threshold` (default 2); below threshold prints `WARN … silent poll N/M`, never `OK` (main.go:252-263, 386-394) | Box is unreachable / off / network-isolated / attestation path down. A box that stops attesting is treated as a potential incident, not assumed healthy | Distinguishes **silent** (no quote) from **verify-failed** (bad quote). **Caveat**: without the monitor running continuously, silence *and* tail-erasure are invisible (threat-model.md:69-70). |
| **on-box verify-audit fail** (boot gate) | `bulkhead-verify-audit.service` non-zero exit blocks the boot; manual: `bulkhead-collector verify-audit /data/bulkhead/audit/provenance.jsonl` prints the first bad record, exits non-zero (verify.go; service:38-51) | A present-but-broken persisted chain: in-place edit, forged insert, reorder/illegal seq-reset, interior/middle-subchain deletion, or cross-chain transplant — all fail closed. Blocks the collector AND every unit that `Requires=` the selftest | **Can't** alter or delete *interior* history without breaking the linkage (the domain is folded into the signed hash — ADR-0013 F4). **Can't be seen on-box**: whole-file deletion or latest-tail truncation (byte-indistinguishable from first boot — verify.go:19-31); a *forged* tail is well-formed JSON so it still fails the sig check. |
| **selftest probe fail** (boot gate) | `bulkhead-selftest.service` logs `SELFTEST FAIL: …` then `log.Fatalf("SELF-TEST FAILED: N probe(s) not denied — refusing to launch services")` (main.go:222-255) | The live confinement floor drifted/failed-open: TCP egress to 1.1.1.1:443 was *not* denied by nftables, or `/usr/.bulkhead-selftest-canary` write was *not* denied by ProtectSystem. Keeps the collector + downstream units down | Proves the kernel egress/FS floor is enforcing before any agent runs. **Caveat**: probe (a) also "passes" pre-DHCP via ENETUNREACH — it confirms "not open", not "network up" (only an ESTABLISHED connection is a failure). |
| **attest gate fail** (posture) | `bulkhead-collector attest gate` exit non-zero; tailnet join refused (`tailscale-up.service` `Requires=` it) | Box booted unarmed, was tampered-to-observe, or a STRANGER is in `tcb_cgroups` (expected exactly 3). E0+E2 not both armed (attest.go:319-358) | **Can't** bring up the tailnet from a non-enforcing posture. **Caveat**: SELF-ASSERTED — a tampered collector that lies about its own maps defeats it (why ADR-0023 layers the crypto self-check). Only the JOIN is gated; serial/local console is break-glass. |
| **crypto self-check fail** (posture) | `bulkhead-collector attest selfcheck`; `bulkhead-attest-selfcheck-gate.service` (ConditionPathExists=/dev/tpmrm0 ⇒ TPM-less box SKIPS) | A fresh-nonce AK-signed PCR-14 quote vs the box's own expected default-armed D failed — catches a **never-armed boot** AND a runtime **map-flip** (booted observe, later faked the live maps; map-read passes, the immutable boot PCR does not) | **Caveat (partial)**: under the shipped qemu default there is no `/data/bulkhead/attest-ak.pin`, so it runs in **structural fallback** (verifies against the quote's own attacker-suppliable AK) — adds freshness + the immutable boot PCR over the map read but does **not** authenticate the TPM or catch a forged collector. The off-box monitor's `attest verify` with a real pin is the stronger check. |
| **degraded to observe** (posture, **silent**) | NOT a unit failure — `systemctl is-active bulkhead-enforce*` may report `active` while live posture is observe. Detect actively: `bulkhead-collector attest gate` (non-zero ⇒ not armed) or `attest status` | An enforce unit lost the boot race / collector wasn't up ⇒ `enforce_flags` left empty ⇒ box degrades to safe OBSERVE (enforce.service:6-8). The BPF-LSM E0/E2 deny layer is silently dropped (structural floor — no-route netns + nftables + egress proxy — still holds) | **Caveat**: there is **NO** shipped `OnFailure=`/alert for degrade-to-observe (ADR-0018 Seam, explicitly deferred). Attacker **can** hide it from a naive `systemctl is-active`; **cannot** hide it from the off-box quote (the posture is in expected-D ⇒ surfaces as `quote-verify-failed`). |
| **PCR-7 unseal fail** (bare metal) | On `BULKHEAD_SEAL_KEY=tpm2`: `LoadCredentialEncrypted` of `audit-seed.cred` fails ⇒ systemd refuses to start the unit; selftest gate keeps everything down (ADR-0008) | Secure Boot state changed (different/unsigned boot chain, TPM clear) ⇒ the seed won't unseal ⇒ fail-closed rather than fresh key over old chains. PCR 7 is stable across RAUC A/B + rollback by design | **Caveat (partial)**: shipped default is `plain` (plaintext 0600-root seed) — PCR-7 sealing is **bare-metal-only**, spike-proven, not live in the VM phase (ADR-0008 Verification; PRODUCTION-READINESS §1 boot-update-attest). PCR 7 is coarse ("booted under our SB key", not the exact kernel). |
| **SEALED AUDIT KEY LOST** (boot) | `bulkhead-seal-audit-key` stops with `SEALED AUDIT KEY LOST`, leaves state untouched, exit 1 (ADR-0030 #2) | Seed absent/unreadable BUT signed chains from a prior boot survive on `/data` (restore that excluded the seed, TPM clear / PCR-7 change). Distinguishes a recoverable operator error from genuine tamper | Self-documenting recovery aid, not a tamper detector. First boot / wiped `/data` has no chains so it never blocks a legitimate mint. Fires only if chains are STILL on `/data` (whole-file erasure is the off-box boundary). |
| **egress-drop rate spike** (kernel log) | `journalctl -k -g bulkhead-egress-drop` or `dmesg \| grep bulkhead-egress-drop` (nftables.conf:84, `policy drop`) | Repeated egress attempts to a non-allowlisted destination — a compromised semi-trusted unit (router/llama/tailscaled/DHCP/DNS) probing the boundary, or a dnsmasq failure (the `anthropic_v4/v6` sets freeze/expire ⇒ legitimate egress also drops, fail-closed by design) | **Caveat**: rate-limited to 10/second, so a high-volume flood is undercounted by design. A confined agent is in a no-route netns and never hits this chain directly (its egress goes via the proxy) — drops here are mostly semi-trusted host units or a netns escape. Code-exec **inside** the floor can't suppress the kernel log without TCB access. |
| **egress-proxy deny records** (chain) | `bulkhead-collector verify-audit /data/bulkhead/audit-egress/provenance.jsonl`, read the `Mode`/`decision` fields; deny reasons `allowlist` / `inspect-unavailable` / `method:<M>` / needle-match (proxy.go:192; ADR-0034 R4/R6/R11) | A cluster of proxy `deny` records = a confined agent attempting forbidden egress on the single mediated untrusted-web path. `inspect-unavailable` flags an inspect host with no loadable re-signing CA (now a fail-closed deny, not a silent downgrade) | The proxy refuses to run if it can't open its signed chain (an unauditable egress boundary fails closed). **Caveat**: proxy writes **2 records per allowed passthrough fetch** — never assert exact chain record counts. Encoded exfil through an *allowed* host is out of scope (R11). Tail-truncation of newest denies is the off-box boundary. |
| **control/broker authority records** (chain) | `verify-audit /data/bulkhead/audit/control.jsonl`; hooks `control:egress-set`/`-clear`, `control:grant-clear`, `control:tcb-register-broker`, `control:enforce-set`; broker chain signs EXPAND/NARROW/DELEGATE/GRANT (ADR-0017 #4) | The tamper-evident record of WHO became TCB, WHICH agent got which egress, WHEN E0/E2 armed/disarmed. An unexpected `tcb-register-broker`, an `enforce-set` disarm, or an `egress-set` wider than policy is an authority anomaly | **Caveat**: AUTH *rejections* are NOT chained (changed no authority; the 0660-root control socket isn't agent-reachable) — a rejected attempt is in the journal, not the chain (ADR-0017 #4). R5 (deferred): the BPF map write lands *first*, then a best-effort append, so a control change can be live-in-map with its record missing — reachable only from the root TCB context, not an agent. `enforce-set` attests uid==0+non-agent, **not which operator**. |
| **crash-looping TCB unit** | `systemctl is-active bulkhead-collector.service`; `systemctl status bulkhead-broker.service`; `journalctl -u bulkhead-collector.service` (rising `NRestarts`, repeated Start/Stop) | The TCB (eBPF path, audit signer, delegation broker) is unhealthy. Cascades: a collector restart RemoveAll-resets `enforce_flags` to observe, de-registers the broker until it re-self-registers, re-runs the enforce/gate units (collector.service:12-13; enforce.service:28-32) | **Caveat**: the Restart/PartOf machinery is *designed* to self-heal common boot races — a transient cold-boot restart is expected; **sustained** looping is the incident signal. A loop that can't come up degrades to observe (off-box-visible only via the quote). |

**Signal count: 13.**

---

## IR lifecycle — numbered playbooks

> **Golden rule (every playbook):** PRESERVE-CHAIN **first**. Export the relevant
> chain(s) + capture a fresh-nonce quote that binds the current HEADs **before** any
> containment action, so the evidence is cryptographically anchored to a moment in time
> *before* you perturb the box. Containment can advance/clear state; the quote + `--since`
> anchor cannot be re-created after the fact.

**Preserve primitives used throughout (run from the management host over the tailnet):**

```sh
# 1. A non-repudiable point-in-time snapshot: a fresh-nonce quote binding the 3 chain HEADs.
NONCE=$(head -c32 /dev/urandom | xxd -p -c64)
ssh root@<device> bulkhead-collector attest quote "$NONCE" > quote-<device>-$(date +%s).json
# 2. A prior-observation anchor (collector:control:broker HEADs; genesis = 64 zeros):
ssh root@<device> bulkhead-collector attest heads
# 3. Ship every chain off-box (live file AND, if rotated, the retained .NNNNNN segments):
ssh root@<device> 'tar -C /data/bulkhead -cf - audit audit-broker audit-router audit-egress' > chains-<device>-$(date +%s).tar
# 4. Render a continuity verdict on the shipped logs against the attested HEAD + a prior pin:
bulkhead-collector verify-audit ./audit/provenance.jsonl \
    --since=<prior-pinned-HEAD> --expect-tip=<quote-bound-HEAD>
```

`--expect-tip` proves the shipped log *is* the one the quote attested; `--since` proves the
prior-observed HEAD is a verified ancestor (no rewind/fork/truncation). Empty
`--since=`/`--expect-tip=` is a fail-closed usage error, never a silently-skipped check
(ADR-0026/0030). The quote binds **3** HEADs (collector/control/broker); the router + egress
chains are verified by the boot gate but are **not** in the quote's ExtraData — preserve them
from disk but you cannot pin them to a quote.

---

### Playbook A — Audit-chain tamper / rewind / truncation (the monitor fires)

**Trigger:** `bulkhead-chain-monitor` emits `chain-rewind-or-fail [<domain>]`, OR an on-box
`bulkhead-collector verify-audit …` exits non-zero.

**TRIAGE**
- Read the alert detail / `BH_ALERT_DOMAIN` to identify which chain (collector/control/broker/router/egress-proxy).
- Run on-box to localize: `bulkhead-collector verify-audit /data/bulkhead/audit/<chain>.jsonl` — it prints the **first bad record** and exits non-zero. This tells you *interior tamper* vs the off-box-only classes.
- Distinguish the cause:
  - **Interior edit / forged insert / reorder / illegal seq-reset / middle-subchain or middle-segment deletion** ⇒ the on-box verify-audit *also* fails (linkage/sig break). Genuine tamper.
  - **Whole-file deletion / latest-tail truncation** ⇒ on-box verify-audit is **silent/green** (byte-indistinguishable from first boot, verify.go:19-31); only the monitor's `--since`/`--expect-tip` fired. This is the class on-box cannot see.
  - **Pruned-segment tamper** (ADR-0040): records older than the retained window (8 MiB × keep) are off-disk ⇒ the monitor's prior-pinned HEAD is no longer found (`foundSince=false`) ⇒ rewind/fork verdict.

**PRESERVE-CHAIN (do this FIRST)**
- Capture quote + heads + the full chain tar (Preserve primitives 1-3 above) **before touching the box**. The monitor's last-good pinned anchor in `state_dir/device-<name>.json` is itself evidence — copy it; it does **not** advance on failure (main.go:332), so it still holds the last verified HEAD.
- If the chain rotated, ship the `.NNNNNN` segments too (Preserve primitive 3 tars the whole dir) — a `--since` anchor pruned on-box is unrecoverable after the prune.

**CONTAIN**
- The tamper itself implies `/data`-write code execution. Cut the blast radius by class:
  - Suspect agent ⇒ Playbook C (NARROW / `systemctl stop`).
  - Suspect a semi-trusted unit (router/proxy) ⇒ `systemctl stop bulkhead-router.service` / restart the proxy (it refuses to run without its signed chain — fail-closed).
  - If you suspect the TCB/`/data` itself, isolate the box from the tailnet (the gate already blocks join on a non-armed posture; you can also `tailscale down` on the management side).

**ERADICATE**
- Interior tamper of a *running* box means the signing path or `/data` is compromised — do **not** trust in-place repair. Re-image via RAUC (Playbook + below): `rauc install /data/<good>.raucb`, reboot, let the selftest+verify-audit gate decide.
- A tampered chain on `/data` **survives a slot rollback** (`/data` is shared across A/B slots) — you must address `/data` state separately; there is no shipped `/data` backup/restore (PRODUCTION-READINESS §1 "Backup & recovery of /data" = absent).

**RECOVER**
- After re-image, confirm the box re-arms: `bulkhead-collector attest gate` (exit 0), and the monitor returns `OK device=<d> attested + N chains continuous`.
- Re-anchor the monitor if the legitimate HEAD/key changed (Known gaps — no re-pin verb; edit/delete `state_dir/device-<name>.json`).

**Limits**
- **Tamper-evident vs erasable:** interior history is tamper-evident (can't alter/delete without breaking linkage). Whole-file erasure and tail truncation are **erasable on-box** and caught **only** off-box. This is an information-theoretic limit (a box can't non-circularly verify its own deletable history against its own deletable anchor — ADR-0030), not a bug. The deferred fix is a TPM-sealed monotonic high-water-mark (PRODUCTION-READINESS §3 boot-update-attest).

---

### Playbook B — Attestation failure / unexpected PCR-7 / boot-gate fail

**Trigger:** `bulkhead-chain-monitor` emits `quote-verify-failed`; OR `attest gate`/`attest
selfcheck` fail; OR (bare metal) a PCR-7 unseal failure refuses unit start; OR `SEALED AUDIT
KEY LOST`.

**TRIAGE**
- Separate the sub-cause:
  - **quote-verify-failed** ⇒ wrong posture (booted observe / map-flipped), replayed old quote, forged/other-box envelope, or wedged TPM. Cross-check: `ssh root@<device> bulkhead-collector attest gate` (posture) and `attest status`.
  - **Unexpected PCR-7 / unseal fail** (bare metal, `BULKHEAD_SEAL_KEY=tpm2`) ⇒ Secure Boot state changed (re-signed/unsigned boot chain, TPM clear). Was there a *legitimate* firmware/SB/kernel-signing change?
  - **SEALED AUDIT KEY LOST** ⇒ seed absent but chains survive ⇒ a restore excluded the seed, or a TPM clear / PCR-7 change. **Recoverable operator error**, not necessarily tamper.
- Confirm whether expected-D drifted because of a *legitimate* collector update (a new binary changes expected-D ⇒ `quote-verify-fail` is expected until you re-anchor — Known gaps).

**PRESERVE-CHAIN (FIRST)**
- The box may still produce a *bad* quote — capture it anyway (`attest quote <nonce>`); the failing envelope is evidence. Capture the monitor's stored pin/state JSON. Ship the chains (Preserve primitives).
- If the box is dark (`missed-attestation`), preserve what the monitor already pinned off-box (`state_dir/device-<name>.json`) — that is your last-known-good HEAD set.

**CONTAIN**
- The attest gate already fail-closes the tailnet join on a non-armed posture (`tailscale-up.service Requires=` the gate). To force isolation: `tailscale down` on the box (serial/local console is break-glass and always survives — ADR-0021).
- If posture is the problem and you want enforcement back without reboot: Playbook D (re-arm E0/E2).

**ERADICATE**
- **Legitimate PCR-7 change**: restore the seed from backup and reboot (the seal script finds it valid and leaves it untouched), OR re-seal a NEW seed with `BULKHEAD_SEAL_FORCE_NEW=1` — **this discards the ability to verify all prior audit history** (a new pubkey under which every prior record fails). Use only if you accept losing prior provenance (ADR-0030 #2; ADR-0008/0028).
- **Forged/replayed quote or map-flip**: treat as TCB compromise ⇒ re-image (Playbook A ERADICATE / the RAUC re-image step).
- **Wedged TPM / TPM clear**: the AK changes ⇒ re-enroll (TOFU `attest akpub`, or the EK-rooted flow `attest ek` → `attest make-credential` → `attest activate` → `attest enroll-verify`) and re-pin the monitor.

**RECOVER**
- After a legitimate change, re-anchor: bump the monitor's `expected_d` (or `collector_bin_for_d` to re-derive it from the released binary) and `audit_pub`, and clear the stale `state_dir/device-<name>.json` for an AK change. Then confirm `OK` from the monitor and `attest gate` exit 0.

**Limits**
- Under the shipped qemu/dev default the AK pin is **blind TOFU / structural fallback** — a software-forged quote is rejected only once an **EK-rooted** pin is provisioned (bare-metal-pending; PRODUCTION-READINESS §2 boot-update-attest). `attest selfcheck` in fallback adds freshness + the immutable boot PCR but does **not** authenticate the TPM.
- The quote attests boot/runtime *posture*, **not** per-agent egress policy and **not** an in-TCB compromise that occurs *after* the boot PCR-14 extend (a compromised collector can quote stale-good values — that is the BPF-LSM floor's job, not attestation's).
- PCR-7 seed-escrow/restore is a **deferred ops seam** — there is no shipped escrow script or restore runbook (ADR-0039:70-72; PRODUCTION-READINESS §1 key-management = partial).

---

### Playbook C — Compromised / misbehaving agent (egress anomaly)

**Trigger:** `bulkhead-egress-proxy` deny-record cluster (`verify-audit
/data/bulkhead/audit-egress/provenance.jsonl`), a `bulkhead-egress-drop` rate spike in the
kernel log, or a broker/control authority anomaly tied to one agent.

**TRIAGE**
- Identify the agent instance and its cgroup: read the proxy/broker/control chains for the offending `cgroup_id`/`comm`/`Mode` fields; map to a `bulkhead-agent@<inst>.service`.
- Check whether E2 is armed (else NARROW won't bite): `bulkhead-collector attest gate` / `attest status`.
- Determine if exfil is over an **already-established** socket (NARROW won't help — it gates only future `connect()`s) vs probing new connects.

**PRESERVE-CHAIN (FIRST)**
- Capture quote + heads + the egress/broker/control chains (Preserve primitives) **before** narrowing or stopping — NARROW and stop both write new records and stopping reaps the agent's manifest/grants (`ExecStopPost`), destroying live state you may want for investigation.

**CONTAIN — escalate from surgical to hard:**
1. **Surgical clamp (no kill, preserves the live process for investigation):**
   ```sh
   bulkhead-collector narrow <instance|agent-slice-path> <classes>   # e.g. narrow narrowee private,public
   ```
   Sends `NARROW` over `/run/bulkhead/approve.sock` (0600 root, SO_PEERCRED uid==0); applies `narrowMask(cur,req)=cur &^ req` to the agent's E2 `egress_policy`, clamping the **named running agent** in place. Refuses an unrestricted (no-manifest) agent with `ERR no-manifest`, and refuses non-agent / `id:N` targets (collector/broker/PID-1/operator session can never be clamped). The clamp is signed onto the broker chain (load-bearing append — `ERR audit` if the record fails). (narrow.go:122-203; ADR-0010)
2. **Impose a manifest on an unrestricted agent** (the case NARROW points you to):
   ```sh
   bulkhead-collector egress set <cgroup> <classes>     # or: egress clear <cgroup>
   ```
   (main.go:297-326). Under armed E0 a direct write from a non-TCB cgroup is EPERM'd — the E0-safe per-agent path is the control-socket self-verb, not this CLI.
3. **Interpose on a pending escalation** (delegate/EXPAND): withholding approval *is* containment.
   ```sh
   bulkhead-collector approve list
   bulkhead-collector approve deny <id>     # or just let it time out (BULKHEAD_APPROVAL_TIMEOUT, default 120s ⇒ deny)
   ```
   (ADR-0007). EXPAND/delegate are narrow-never-widen (child = parent ∩ requested) so even an approved request can't widen past the parent.
4. **Hard stop (kills the process AND its established sockets):**
   ```sh
   systemctl stop bulkhead-agent@<inst>.service     # or systemctl kill
   ```
   `ExecStopPost` clears the egress manifest, unconsumed E1/E3 grants, and reaps the `/run` drop-in + task credential so a recycled cgroup inherits nothing (agent@.service:53-62). Use this when the agent is actively exfiltrating over an open connection.

**ERADICATE**
- A delegated **child** is a separate `bulkhead-agent@d-<hex>-<suffix>` instance — stop it individually, or stop the whole `bulkhead-agent.slice` to take down a lineage.
- If the agent escaped its netns or compromised a semi-trusted unit, escalate to Playbook A/B (chain/TCB integrity) and consider re-image.

**RECOVER**
- A NARROW clamp is **live BPF-map state only**: an agent **restart re-applies its configured manifest** via `+ExecStartPre … egress set self`. To make the clamp stick across restart, edit the instance drop-in (`BULKHEAD_AGENT_EGRESS`) — otherwise the clamp evaporates on the next start.

**Limits**
- **NARROW gates FUTURE connects only** (E2 hooks `socket_connect`); an already-ESTABLISHED socket survives until it closes — for a hard stop use `systemctl stop`.
- NARROW/`egress set` only bite when **E2 is armed** (`bulkhead-enforce-egress`). Below E2 the structural floor still applies (no-route netns + nftables drop + fail-closed egress proxy), but the per-agent *class* restriction is not enforced.
- Encoded/encrypted exfil through an *allowed* host is inherent to any denylist and out of scope (ADR-0034 R11).

---

### Playbook D — An enforce-unit degraded to observe

**Trigger:** off-box `quote-verify-failed` (expected-D pins the `enforce_flags` posture, so
observe ≠ expected-D); OR an active poll of `attest gate` returns non-zero while
`systemctl is-active bulkhead-enforce*` still says `active`.

**TRIAGE**
- **Do not trust unit state.** Query the *live posture*: `bulkhead-collector attest gate` (exit non-zero ⇒ not armed) or `attest status`. The oneshot/RemainAfterExit enforce unit can report `active` while the box runs observe (enforce.service:28-31).
- Determine why it degraded: a collector that wasn't up, the E2 boot race, or a broker not yet TCB (E0's `ExecStartPre=ctl wait-broker-tcb` gate). Check `journalctl -u bulkhead-collector.service -u bulkhead-broker.service` for a crash/restart that RemoveAll-reset `enforce_flags`.

**PRESERVE-CHAIN (FIRST)**
- Capture a quote (it records the observe posture in PCR-14/expected-D — evidence that the box was degraded at time T) + the control chain (an `control:enforce-set` disarm, if any, is signed there).

**CONTAIN / ERADICATE — re-arm without reboot:**
```sh
systemctl start bulkhead-enforce          # re-arm E0 (ExecStartPre ctl wait-broker-tcb, then enforce on bpf)
systemctl start bulkhead-enforce-egress   # re-arm E2 (per-agent socket_connect egress)
# equivalently: bulkhead-collector enforce on bpf | enforce on socket_connect
```
Disarm (soft, no reboot) is the inverse: `systemctl stop bulkhead-enforce` runs
`ExecStop=… enforce off bpf`, which **routes the write through the collector control socket**
(`ENFORCE-SET <hook> 0`) so the `bpf()` is issued from the collector's TCB context and actually
takes effect under armed E0 (ADR-0016 — pre-ADR-0016 a direct `enforce off bpf` from the unit's
own non-TCB cgroup was EPERM'd and the kill-switch silently failed).

The single authority chokepoint is the control-socket verb `ENFORCE-SET` on
`/run/bulkhead/control.sock` (0660 root:root): it authenticates every connection (SO_PEERCRED
uid==0 + SO_PEERPIDFD cgroup) and **rejects agent cgroups** (`ERR not-operator`), so a jailed
lineage can never flip the master switch (ADR-0024).

**RECOVER**
- After re-arm, confirm `attest gate` exit 0 and the monitor returns `OK`. A collector restart auto-re-arms both (PartOf= restarts the oneshots, which re-run `wait-broker-tcb` + `enforce on`).

**Limits**
- **There is NO shipped on-box alert for degrade-to-observe** — an `OnFailure=` off-box signal is an explicitly deferred seam (ADR-0018 Seam; PRODUCTION-READINESS §2 "Operator-visible booted UNARMED signal"). A deployment that treats observe-when-it-should-enforce as an incident **must** detect it actively (poll `attest gate`) or rely on the monitor's `quote-verify-failed`.
- Disarming is fail-**open**: E2 disarm can only fail to *add* a denial, never open the nftables floor (security-review R-final). Re-arm is the only fix; the box never bricks on a failed arm (degrade-to-observe by construction).

---

### Playbook E — A failed / crash-looping TCB service (collector / broker / proxy / router)

**Trigger:** `systemctl is-active bulkhead-collector.service` non-active; `systemctl status
bulkhead-broker.service` shows repeated Start/Stop with a rising `NRestarts`; possibly an
accompanying `missed-attestation` if the collector can't produce a quote.

**TRIAGE**
- `journalctl -u bulkhead-collector.service -u bulkhead-broker.service` — count restart cycles. Collector and broker are `Restart=on-failure RestartSec=2`; the broker is `PartOf=bulkhead-collector.service` (a collector restart restarts it to re-self-register TCB).
- A **transient** restart at cold boot is expected (the machinery self-heals boot races, ADR-0018 #6). **Sustained** looping is the incident signal.
- Understand the cascade: a collector restart RemoveAll-resets `enforce_flags` to observe (⇒ Playbook D), de-registers the broker until it re-self-registers, and re-runs the enforce/gate units. A broker that crash-loops leaves E0 unable to arm (the `wait-broker-tcb` gate, enforce.service:37-38).

**PRESERVE-CHAIN (FIRST)**
- If the collector is the looping service it may be unable to sign or quote — capture whatever the box still produces, the journal, and the on-disk chains (Preserve primitive 3). The monitor's last-good off-box pin is your continuity anchor if the on-box signer is down.

**CONTAIN**
- A looping collector means the box has likely degraded to observe — apply Playbook D once it stabilizes. If the loop indicates compromise rather than a transient fault, isolate from the tailnet (`tailscale down`; the attest gate already blocks join on the non-armed posture).

**ERADICATE**
- If the loop is a transient boot race, let `Restart=`/`PartOf=` converge (it is designed to). If it persists, escalate to re-image (RAUC) — a TCB service that won't come up is a hardened-slot health failure.

**RECOVER**
- After the service stabilizes, confirm: `systemctl is-active bulkhead-collector.service` active, `attest gate` exit 0, both enforce units re-armed, and the monitor `OK`.

**Limits**
- A crash-loop that fails to come up **degrades to observe**, which is itself only off-box-visible via the quote (Playbook D limits).
- ADR-0018 Seam **defers** the RAUC posture decision on whether a hardened slot whose broker crash-loops should auto-roll-back vs the current never-brick degrade-to-observe default — so there is no automatic rollback on a TCB crash-loop today; the operator decides.

---

### Whole-image containment / recovery (RAUC) — used by Playbooks A, B, E

When eradication needs a clean rootfs (compromised TCB, tampered binary, bad update):

```sh
rauc status                                   # inspect slot health first
rauc install /data/<good-bundle>.raucb        # writes the INACTIVE slot only; CMS sig + dm-verity verified BEFORE any write
rauc status mark-bad booted                   # demote the currently-booted (bad) slot
systemctl reboot                              # next boot falls back to the prior good slot
```

- `rauc install` verifies the bundle's CMS signature + dm-verity against the device keyring (`/etc/rauc/ca.cert.pem`) **before** touching a slot — a non-bundle blob or wrong-key bundle is rejected without writing anything (ADR-0039; scripts/qemu-rauc-check.py:80).
- **Automatic health-rollback:** `rauc-mark-good.service` is gated (`Requires=/After= bulkhead-selftest.service bulkhead-verify-audit.service`) — a freshly-installed slot is only PINNED (`_TRY=0`) if the security gates passed; a gate failure leaves `_TRY=1` and the **next** reboot auto-rolls-back (ADR-0039). Verify the coupling is live: `systemctl show rauc-mark-good.service -p After -p Requires` must list both bulkhead gates.
- **No-downgrade floor:** `min-bundle-version=0.1.0` + a CMS-signed in-bundle install-check hook reject a stale signed bundle (blocks replaying a patched CVE — ADR-0039).

**Limits:** rollback authenticates the **bundle** at install, **not** the booted root (no dm-verity on the running ext4 — ADR-0039 info-finding); no CRL / signer-CN pinning (a leaked HSM signer key can't be revoked on-device). Rollback reverts the **rootfs slot only** — the persistent `/data` partition (audit chains, tailscaled state, model, sealed seed, MITM CA) is **shared across slots and is NOT reverted**, so a compromise that persisted state on `/data` (a tampered chain, a planted seed) survives a slot rollback. Both slots can hold the same bad image if the operator updated twice. **Do NOT** `systemctl stop bulkhead-firewall.service` as a containment action — its `ExecStop=-/usr/sbin/nft flush ruleset` *flushes* the default-deny floor (widens, not narrows).

---

## Known gaps / pending

These are real IR limits today. An operator must not assume a capability this section flags
as absent/partial. Cross-reference `docs/PRODUCTION-READINESS.md` §1 (Pilot blockers) and §3
(Hardening).

1. **The off-box monitor is not yet *deployed* as an always-on service.** The mechanism is
   shipped and live-proven (`bulkhead-chain-monitor`, `make verify-chain-monitor[-live]`), but
   the operational deployment — run it always-on against the real fleet, wire `alert_cmd` to a
   real on-call path, pin the TOFU AK + initial HEADs at provisioning — is **partial/pending**
   (PRODUCTION-READINESS §1 "Off-box audit-chain monitor + alerting deployed"). Without it
   running continuously, silence and tail-erasure are invisible.

2. **No on-box detection of whole-file erasure / tail truncation.** Information-theoretic limit
   (ADR-0030); caught **only** off-box. The deferred fix is a TPM-sealed monotonic
   high-water-mark (PRODUCTION-READINESS §3 boot-update-attest) — **unbuilt**.

3. **Rotated/segmented chains (ADR-0040) are not yet fully covered off-box.** The example
   `fetch_chain_cmd` ships only the live `*.jsonl`; once a chain rotates, `verify-audit` needs
   the retained `.NNNNNN` segments **and** the `--since` anchor must have been archived off-box
   **before** the on-box prune (8 MiB segments, keep 1). Extending the monitor to ship/extract
   segments is a tracked **follow-up** (deploy/chain-monitor.md:43-50). Rely on full forensic
   depth only if the off-box archival pull runs **faster** than the prune cadence; non-rotated
   chains are fully covered today.

4. **PCR-7 seed-escrow / restore path is a deferred ops seam.** Bare-metal `tpm2` sealing is
   spike-proven but not live in the VM phase (shipped default is `plain`). There is **no**
   escrow script and **no** tested restore runbook after a legitimate PCR-7 perturbation — a
   firmware/SB-key/TPM-RMA change bricks the box until the seed is restored from backup, and
   there is **no shipped `/data` backup/restore** (ADR-0039:70-72; PRODUCTION-READINESS §1
   key-management = partial, "Backup & recovery of /data" = absent).

5. **Audit-key rotation has no continuity story.** Rotating the signing seed mints a new pubkey
   under which ALL prior records fail verification — a **hard break** of cross-boot chain
   continuity. The only sanctioned rotation is `BULKHEAD_SEAL_FORCE_NEW=1`, which **explicitly
   discards prior history**. There is no shipped key-rollover / domain-version mechanism (AK↔seed
   binding deferred, ADR-0020:91-96). Treat seed rotation as history-discarding, not hygiene.

6. **No first-class re-pin verb on the monitor.** Re-anchoring a legitimately-changed AK/HEAD
   means manually editing or deleting `state_dir/device-<name>.json` and bumping
   `expected_d`/`collector_bin_for_d`/`audit_pub` — a documentation gap, not an automated path.

7. **No operator identity on disarm.** `control:enforce-set` attests only uid==0 + non-agent —
   **not which operator** flipped the master switch. An `enforce-set` disarm record carrying an
   operator identity is a deferred item (PRODUCTION-READINESS §3 "Signed control-socket writes:
   off-box anchor + operator identity").

8. **Control-plane record-after-act (R5, deferred).** Control handlers apply the BPF map write
   **first**, then best-effort append the signed record, so a control authority change can be
   live-in-the-map while its signed record is missing (an un-chained journal line notes it).
   Reachable only from the root TCB context, not an untrusted agent (security-review R5).

9. **EK-rooted attestation is bare-metal-pending.** Under the shipped qemu/dev default the AK
   pin is **blind TOFU / structural fallback** — a software-forged quote is rejected only once an
   EK-rooted pin is provisioned (ADR-0019/0020 Seam; PRODUCTION-READINESS §2 boot-update-attest).
   `attest selfcheck` in fallback does not authenticate the TPM.

10. **No metrics/observability surface.** A failing-but-not-crashed TCB service is invisible
    except via `journalctl`/`systemctl status` and the off-box quote — there is no scrapeable
    metrics surface (PRODUCTION-READINESS §1 "Operational metrics" = absent), so deny-rate /
    chain-append-error / broker-queue signals must be read from logs and chains by hand.

11. **No external red-team / third-party audit.** Every detection and containment claim here
    rests on first-party self-review (`docs/security-reviews/2026-06-shipped-isolation-review.md`)
    (PRODUCTION-READINESS §2 external-validation = absent).
