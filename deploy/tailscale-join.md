# Joining the appliance to your tailnet

bulkhead is **tailnet-only inbound**: `tailscaled` runs idle until the node
joins, and the router rebinds its listener to the tailnet address so it is
reachable only over Tailscale. The auth key is delivered at runtime and is never
committed or baked into an image.

## Egress

The nftables floor permits the Tailscale **control plane** (`192.200.0.0/24`,
`199.165.136.0/24` on tcp/80,443), STUN (udp/3478), and WireGuard (udp/41641).
DERP relays live on many dynamic IPs; the production build resolves
`derpN-all.tailscale.com` into a `tailscale_v4` set via dnsmasq (the same dynamic
allowlist that covers `api.anthropic.com`). In qemu the node authenticates and
joins via the control plane; full DERP relaying needs that dynamic allowlist.

## Provide the key (never in the repo or an image)

Generate an **ephemeral, tagged, short-expiry** key in the Tailscale admin
console. Two delivery options:

**Production — sealed credential (preferred):**
```sh
printf '%s' "$TS_AUTHKEY" | systemd-creds encrypt --name=tailscale-authkey --with-key=tpm2 - \
  /etc/bulkhead/tailscale-authkey.cred
# (host key in the qemu/vTPM phase; see deploy/anthropic-credential.md)
```
then a `tailscale-up.service` drop-in with `LoadCredentialEncrypted=` and
`--auth-key=file:$CREDENTIALS_DIRECTORY/tailscale-authkey`.

**Prototype — provisioning volume:** write the key to `~/.bulkhead/tsauthkey`
on the build host, then:
```sh
make tsauth-disk     # builds output/images/tsauth.ext4 (key inside, gitignored)
make run             # attaches it as /dev/vdc; tailscale-up reads file:/mnt/tsauth/authkey
```
After the node joins, detach the volume — `tailscaled` keeps its state in
`/var/lib/tailscale`.

## What happens at boot

`mnt-tsauth.mount` → `tailscale-up.service` (`tailscale up --auth-key=file:…`) →
`bulkhead-router-bind.service` writes `BULKHEAD_LISTEN=<tailnet-ip>:8080` →
`bulkhead-router` binds the tailnet address. With no key volume, all of this is
skipped and the router stays on loopback.

> Rotate any key that has been exposed (e.g. pasted into a chat or log).

## Posture gate (ADR-0021) — the join is load-bearing on enforcement

`tailscale-up.service` `Requires=bulkhead-attest-gate.service` and re-checks in an
`ExecStartPre`, so the node **joins the tailnet only when the box is in the
expected enforcing posture**: E0 (`lsm/bpf` deny) armed **and** E2
(`socket_connect` deny) armed **and** `tcb_cgroups` clean, read live from the
pinned BPF maps by the collector (TCB). A disarmed, failed-to-arm, or
TCB-strangered box **cannot bring up the tailnet**. This first gate is a
self-asserted posture predicate (a tampered collector defeats it), conditioned on
the collector **binary** so it gates a TPM-less box too.

**Second gate (ADR-0023, cryptographic):** `tailscale-up.service` ALSO
`Requires=bulkhead-attest-selfcheck-gate.service`, which has the box produce a
fresh-nonce **TPM-signed** quote and verify it against the expected default-armed
D it derives from its own binary — so the join additionally depends on a genuine,
fresh, boot-PCR-matching proof, not just a map read. This second gate
`ConditionPathExists=/dev/tpmrm0`, so on a **TPM-less** box it is condition-skipped
and only the map-read gate applies (augment, never replace — a crypto-only gate
would fail-open the no-TPM box). It is a **same-box self-check**, strictly weaker
than the off-box relying-party `attest verify`: it proves the quote is genuine +
fresh + matches the box's own boot-extended, self-derived D, **not** that the box
is unmodified (a binary swap self-passes; a runtime post-boot compromise is not
caught). A pre-provisioned EK-rooted pin at `/data/bulkhead/attest-ak.pin` (from a
one-time off-box ADR-0020 enroll) adds this-TPM identity; absent it, the
structural fallback verifies under the quote's own AK without an identity claim.

Polarity is deliberately the opposite of ADR-0018's fail-safe: the gate **blocks**
on observe. Blocking the tailnet is **not a brick** — only the *join* is gated;
the serial/local console, local login, and `tailscaled` itself always survive.

**Break-glass** (recover tailnet access on a deliberately-disarmed box, from the
console):

1. **Re-arm (intended in-band recovery):**
   ```sh
   systemctl start bulkhead-enforce-egress.service bulkhead-enforce.service
   systemctl restart bulkhead-attest-gate.service              # map-read gate re-passes once armed
   systemctl restart bulkhead-attest-selfcheck-gate.service    # crypto gate (TPM box only; condition-skipped without a TPM)
   systemctl start tailscale-up.service                        # rejoins
   ```
   Re-arm is the **supported recovery** — prefer it.
2. **Persistent observe-mode downgrade (deliberate soak/debug box):** do **not**
   `systemctl mask bulkhead-attest-gate.service` — a masked `Requires=` is a hard
   `Unit bulkhead-attest-gate.service is masked` transaction failure, so masking
   makes `tailscale-up` *refuse to start* and **bricks the rejoin after a reboot**
   (a masked dependency is NOT vacuously satisfied — only a *condition-skipped* one
   is). To run a box in observe mode that still joins, **edit the base
   `tailscale-up.service`** to drop (or change to `Wants=`) the
   `Requires=bulkhead-attest-gate.service` line **and** clear the `ExecStartPre=`
   re-check. A drop-in cannot empty a dependency list, and clearing only the
   `ExecStartPre` is insufficient (the hard `Requires=` edge still refuses the
   start). This is a conscious posture **downgrade** that removes the load-bearing
   guarantee.
3. **Console backstop:** console root already has authority equal to `systemctl
   stop bulkhead-enforce`, so no kernel-cmdline/env bypass is added — recover via
   (1) or (2). Sharp edge: an operator who soft-disarms a **remote** box over the
   tailnet keeps the *current* session but will **not** rejoin after a reboot (a
   not-armed gate refuses the join) — **re-arm before rebooting**. Masking the gate
   does NOT help (it makes the rejoin fail outright); only the base-unit downgrade
   above, or re-arming, restores rejoin.
