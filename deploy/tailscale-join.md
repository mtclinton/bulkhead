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
TCB-strangered box **cannot bring up the tailnet**. This is a self-asserted
posture predicate (a tampered collector defeats it), **not** a TPM-quoted
off-box proof — that is the follow-up that consults `attest verify` against an
EK-rooted quote.

Polarity is deliberately the opposite of ADR-0018's fail-safe: the gate **blocks**
on observe. Blocking the tailnet is **not a brick** — only the *join* is gated;
the serial/local console, local login, and `tailscaled` itself always survive.

**Break-glass** (recover tailnet access on a deliberately-disarmed box, from the
console):

1. **Re-arm (intended in-band recovery):**
   ```sh
   systemctl start bulkhead-enforce-egress.service bulkhead-enforce.service
   systemctl restart bulkhead-attest-gate.service   # re-passes once armed
   systemctl start tailscale-up.service             # rejoins
   ```
2. **Mask (deliberate, persistent observe-mode soak/debug box):** `systemctl mask
   bulkhead-attest-gate.service` makes the `Requires=` vacuously satisfied — but
   you must **also** neutralize the `ExecStartPre` re-check (a `tailscale-up.service`
   drop-in that clears `ExecStartPre=`, or simply keep enforce armed). This is a
   conscious posture **downgrade** that removes the load-bearing guarantee;
   reversible with `systemctl unmask`, and auditable via `systemctl is-enabled`.
3. **Console backstop:** console root already has authority equal to `systemctl
   stop bulkhead-enforce`, so no kernel-cmdline/env bypass is added — recover via
   (1) or (2). Sharp edge: an operator who soft-disarms a **remote** box over the
   tailnet keeps the *current* session but will **not** rejoin after a reboot —
   re-arm before rebooting, or pre-stage the mask.
