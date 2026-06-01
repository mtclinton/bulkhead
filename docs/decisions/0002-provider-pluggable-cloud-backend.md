# ADR 0002 — Provider-pluggable cloud backend

- **Status:** Accepted
- **Date:** 2026-05-30
- Supersedes nothing; refines the model-routing pillar of
  [ADR 0001](0001-foundational-architecture.md).

## Context

The question arose whether to incorporate OpenAI and Google Gemini as cloud
backends alongside Anthropic, motivated by a belief that Anthropic API tokens
are expensive / "must be purchased separately" and that OpenAI and Gemini are
"more willing to be used for API work" (citing the OpenClaw controversy).

We checked the premises (May 2026):

- **Pricing is not the differentiator some assume.** At comparable tiers
  Anthropic is competitive or cheaper: Sonnet 4.6 ($3/$15 per 1M in/out) ≈
  GPT‑5.4 ($2.50/$15); Opus 4.7 ($5/$25) undercuts GPT‑5.5 ($5/$30). The only
  clear wins for others are rock-bottom bulk tiers (Gemini Flash‑Lite
  $0.10–$0.40, GPT Nano $0.20/$1.25) — and **bulkhead routes bulk/cheap work to
  the tokenless local tier**, so the cloud tier is a frontier-quality concern
  where Anthropic is competitive. All three meter tokens and require a prepaid
  billing account; none is uniquely "separate."
- **"More willing for API work" is contradicted by the evidence.** In the
  OpenClaw episode, Google **cut OpenClaw users off from Gemini/Antigravity
  without warning** after a spike in agentic token consumption it deemed
  "malicious use of the backend." For an appliance that *generates* high-volume
  autonomous-agent traffic, depending on Gemini as the default is an
  operational risk, not a safer bet. The sanctioned path on every provider is
  the metered API; consumer subscriptions used programmatically violate ToS
  everywhere (which is why bulkhead keeps the Claude Max tier to interactive use
  only — see ADR 0001).
- **OpenClaw is the cautionary tale bulkhead is built to contain** (rogue agent
  with full authority, data exfiltration, supply-chain compromise via a poisoned
  npm token, unbounded backend spend). Every one of those is a failure mode the
  kernel isolation, capability grants, default-deny egress, provenance log, and
  pinned-hash/SBOM supply chain address. This validates the thesis rather than
  arguing for a provider swap.

## Decision

1. **The cloud backend is a pluggable provider interface**, not hardcoded to one
   vendor. This generalizes ADR 0001's "model routing, each route its own
   auth/policy" pillar to N providers.
2. **Anthropic is the default**, swappable per deployment by configuration
   (not code). It is competitive at the frontier, coherent with the interactive
   Claude tier, and not subject to Gemini-style agentic-traffic bans.
3. **OpenAI and Gemini are optional, post-v1 provider implementations.** v1 ships
   **Anthropic-only**; adding a provider is a new `Backend` implementation + a
   key + an egress-allowlist entry, never a v1 blocker.
4. **Cost is explicitly not the design driver.** The local tier absorbs
   cost-sensitive volume; bulkhead's buyers care about control, audit, and
   compliance, where token cost is not decisive.

## Consequences

- The router already isolates the cloud call (`proxyAnthropic`); when providers
  are added, that becomes one implementation of a small `Backend` interface
  (`translate`/`call`), each with its own key source and egress allowlist.
- Per-provider auth/policy stays explicit: own runtime-delivered key, own
  `api.<provider>` egress entry, own ToS-compliant usage.
- v1 scope is unaffected. Multi-provider is a roadmap increment, prioritized by
  real demand, not by the (debunked) cost premise.

## Implemented

OpenAI + Gemini land as a `Backend` interface (`src/router/provider.go`): Anthropic keeps
its translation (`anthropicBackend`), OpenAI + Gemini share one `openAICompatBackend`
(OpenAI-compatible passthrough — Gemini via its `/v1beta/openai` endpoint). `selectProvider`
(route.go) picks the vendor by model prefix (`claude*`/`gpt*`/`o1,o3,o4*`/`gemini*`, else a
configured `BULKHEAD_API_PROVIDER` default) and runs ONLY after `decide()` returned
RouteAPI — so it picks the vendor, never the tier: the prompt-length denial-of-wallet gate
is unchanged. Per-provider invariants preserved: key-from-file-only, `validateBase`
host-pin over TLS (a key only reaches its own host), the single no-redirect client (no
cross-host key exfil), req/resp caps, generic client errors, and a re-marshalled upstream
body (`openAIUpstreamRequest`) that cannot leak the bulkhead-only `route` field. A missing
provider key 503s that provider only. The dnsmasq→nftset egress allowlist gains
per-provider sets for `api.openai.com` + `generativelanguage.googleapis.com` (nftables.conf
+ dnsmasq.conf + the pre-warm). Streaming stays uniformly rejected; seams left for
per-provider model maps + streaming. Unit-tested (selection, denial-of-wallet, shaping, key
isolation, no-redirect) + qemu egress-verified; keys are TPM-/credential-bound per ADR-0008.

## Sources

- Anthropic pricing: <https://www.tldl.io/resources/anthropic-api-pricing>
- OpenAI pricing: <https://www.cloudzero.com/blog/openai-pricing/>
- Gemini pricing: <https://ai.google.dev/gemini-api/docs/pricing>
- Google bans OpenClaw/Antigravity use:
  <https://venturebeat.com/orchestration/google-clamps-down-on-antigravity-malicious-usage-cutting-off-openclaw-users>
- Poisoned npm → OpenClaw:
  <https://www.csoonline.com/article/4135449/compromised-npm-package-silently-installs-openclaw-on-developer-machines.html>
