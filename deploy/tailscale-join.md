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
