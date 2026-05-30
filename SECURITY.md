# Security policy

bulkhead is a hardened agent appliance; its threat model is in
[docs/threat-model.md](docs/threat-model.md).

## Status

Pre-release (milestone v1 in progress). There are no supported releases yet, and
no security guarantees are made about pre-release builds.

## Reporting a vulnerability

Please report security issues privately via a
[GitHub security advisory](https://github.com/mtclinton/bulkhead/security/advisories/new)
rather than a public issue. A maintainer will acknowledge and triage. Coordinated
disclosure is appreciated.

## Posture (design intent)

- **No secrets in the repo or in images.** The Anthropic API key and any other
  secrets are delivered at runtime via TPM-bound systemd credentials. CI gates
  every push/PR with a secret scan.
- **Fail-closed enforcement.** Confinement (seccomp + Landlock + dropped
  capabilities + namespaces) is applied at process launch; a boot self-test
  attempts forbidden actions and refuses to launch services if they are not
  denied. eBPF provides observe-only provenance, never the sole enforcement
  gate.
- **Default-deny network.** Inbound is Tailscale-only; egress is default-deny
  except the Anthropic API and model fetches.
- **Tamper-evident provenance.** Security-relevant actions are recorded in a
  hash-chained, Ed25519-signed, append-only audit log.
