# Delivering the Anthropic API key

The Anthropic API key is **never** committed to this repository or baked into an
image. It is delivered to `bulkhead-router` at runtime as a systemd-encrypted
credential, decrypted only into the unit at
`/run/credentials/bulkhead-router.service/anthropic-api-key` (tmpfs, noswap,
mode 0400). The router reads it from `$CREDENTIALS_DIRECTORY` and sends it only
as the `x-api-key` header to `api.anthropic.com` — never logged, never echoed.

## Seal the key (run on the appliance, over Tailscale SSH)

**Bare metal — TPM2-bound (preferred):**

```sh
printf '%s' "$ANTHROPIC_API_KEY" | \
  systemd-creds encrypt --name=anthropic-api-key --with-key=tpm2 - \
  /etc/bulkhead/anthropic-api-key.cred
```

**qemu / vTPM phase — host key:** the vTPM `tpm2` unseal path is unreliable
(systemd #21747), so bind to the persistent host key instead:

```sh
printf '%s' "$ANTHROPIC_API_KEY" | \
  systemd-creds encrypt --name=anthropic-api-key --with-key=host - \
  /etc/bulkhead/anthropic-api-key.cred
```

The key is piped via stdin so the plaintext never lands on disk. The resulting
`.cred` is opaque without the (v)TPM/host key and is safe at rest — but it is
still environment-specific and must not be committed.

## Wire it into the unit

Drop-in `/etc/systemd/system/bulkhead-router.service.d/10-anthropic-key.conf`:

```ini
[Service]
LoadCredentialEncrypted=anthropic-api-key:/etc/bulkhead/anthropic-api-key.cred
```

Then `systemctl daemon-reload && systemctl restart bulkhead-router`.

Without this drop-in (e.g. the bare qemu prototype) the router still starts:
`local` routes work and `api` routes return `503` until a key is present.

## Verify

```sh
systemctl show bulkhead-router -p LoadCredentialEncrypted
ls -l /run/credentials/bulkhead-router.service/   # anthropic-api-key, 0400 root
```
