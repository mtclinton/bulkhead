# Contributing to bulkhead

bulkhead is a security-focused systems project. Contributions are welcome, but
the bar is correctness and a small, auditable trusted computing base over
features.

## Commit conventions

- **[Conventional Commits](https://www.conventionalcommits.org/).** Format:
  `<type>(<scope>): <description>`. Types: `feat`, `fix`, `docs`, `build`, `ci`,
  `refactor`, `test`, `chore`. Breaking changes use `!` or a `BREAKING CHANGE:`
  footer. Example: `feat(router): route by prompt-length rule to local llama.cpp`.
- **Single human author per commit.** No `Co-Authored-By:` trailers, no
  AI/"Generated with" attribution, no third-party trailers. This is enforced in
  CI (`.github/workflows/authorship.yml`) — commits carrying such metadata fail
  the build.

## Secrets

No credential, API key, or private key may be committed or baked into an image,
ever. Secrets are supplied at runtime from the environment or a secret store.
A [gitleaks](https://github.com/gitleaks/gitleaks) scan runs on every push/PR;
install the local pre-commit gate with `pre-commit install`.

## Code

- **Go**: `gofmt`, `go vet`, table-driven tests. The provenance collector is
  pure Go (`CGO_ENABLED=0`, [cilium/ebpf](https://github.com/cilium/ebpf)) so it
  ships as a single static binary; do not introduce CGO dependencies.
- **BPF C** (`*.bpf.c`): kept in separate compilation units, licensed `GPL` in
  the `SEC("license")` string (required by the verifier for GPL-only helpers).
- **SPDX**: every source/config file carries
  `SPDX-License-Identifier: AGPL-3.0-only` (use the appropriate comment syntax).

## Building

See the [README](README.md). `make help` lists the build targets.
