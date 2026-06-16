# ADR-0037: Multi-agent topology: each agent a separate isolation domain with mediated IPC

Status: Proposed — delegation-chain resource-authority bound shipped + live-proven 2026-06-15
Date: 2026-06-07
Pillar: action-authorization
Relates to: ADR-0031/0032 (each agent domain reuses the substrate), ADR-0035 (action authorization); relates to ADR-0006 (inter-agent egress delegation) and ADR-0015 (sub-agent orchestration).

## Context and problem statement

Bulkhead's single-agent guarantees — separate-kernel isolation (ADR-0031/ADR-0032), structural egress (ADR-0034), default-deny resource authorization (ADR-0035) — are scoped to one agent in one domain. The moment two agents collaborate, delegation introduces attack surface that single-agent isolation does not cover [#25]:

- **Injection laundering:** one agent's output becomes another agent's trusted input, so untrusted content that a downstream agent would never have ingested directly arrives wearing the upstream agent's credibility [#25].
- **Cross-agent privilege escalation:** a low-authority agent induces a higher-authority peer to act, re-aggregating authority that no single agent legitimately holds [#25].
- **Authority asymmetry / identity gap:** A2A's identity model is transport-only, with optional agent-card signing — it authenticates a channel, not the authority a request actually carries [#25].

The design question: when bulkhead hosts multiple agents, do they share a trust pool, or is each a first-class boundary with mediated, authority-preserving communication?

## Decision drivers

- A shared trust pool makes every per-agent OS guarantee only as strong as the weakest collaborating agent — injection laundering routes around all of them [#25].
- The altitude test: cross-agent isolation is a single-trace, completely-mediatable boundary and therefore the right kind of property to lower to the OS, consistent with the isolation pillar's verdict [#16].
- Transport-only A2A identity cannot be the authorization substrate; authority must be carried and checked explicitly, not inferred from the channel [#25].
- Consistency with the existing model: agents are already untrusted (ADR-0035); a second agent is just another untrusted principal, not a trusted helper.

## Considered options

1. **Shared trust pool (collaborating agents in one domain / shared context).** Rejected. This is the default multi-agent posture and the exact thing the evidence indicts: it converts every delegation into an unmediated authority transfer and makes injection laundering a one-hop bypass of per-agent isolation [#25].

2. **Rely on A2A protocol identity (signed agent cards, authenticated transport).** Rejected as the boundary. A2A identity is transport-only with optional card signing; it tells you who you are talking to, not what authority the message may exercise, and does nothing about authority asymmetry across a chain [#25]. Useful as an authentication input, never as the authorization mechanism.

3. **Per-agent isolation domains with mediated, authority-preserving IPC.** Accepted. Each agent is its own domain (reusing the same isolation substrate and resource mediation as a solo agent); all inter-agent communication passes through a bulkhead-mediated channel that preserves and checks authority rather than pooling it [#25].

## Decision

Bulkhead WILL treat **each agent as its own isolation domain**. There is no shared trust pool. All inter-agent communication WILL flow through a bulkhead-mediated IPC channel; there WILL be no direct agent-to-agent path. The mediated channel WILL preserve authority — a delegated request carries explicit, checkable authority and is subject to the same default-deny resource authorization (ADR-0035) as any other action — so that a downstream agent never silently inherits an upstream agent's privileges. The authority representation starts from bulkhead's **already-shipped monotone-attenuating delegation model** (ADR-0006/0015, `src/collector/broker.go`): a child's grant is `parent ∩ requested` (widening is arithmetically impossible), depth-capped, and lifetime-clamped (`BULKHEAD_AGENT_NO_EXPAND`), so authority can only attenuate across hops. Generalizing that egress-class bitmask into a full cross-domain authority token — and its attenuation/budget semantics — is the open design item below; this ADR commits firmly to the **topology** (per-agent domains, mediated IPC, cross-domain-input-is-untrusted) and to attenuation-not-amplification, and defers the concrete token format. Cross-domain messages WILL be treated as untrusted input on receipt. A2A/transport identity MAY be used to authenticate peers but WILL NOT be used to authorize actions.

## Consequences

### Positive

- Per-agent OS guarantees (isolation, egress, resource authorization) compose instead of degrading to the weakest collaborator; a compromise stays bounded to one domain [#25].
- Injection laundering loses its free hop: cross-domain output is untrusted input by construction, not trusted-because-it-came-from-a-peer.
- Reuses bulkhead's existing primitives — a delegation is just mediated IPC plus an authorization check, no new trust class.

### Negative / costs

- A mediated IPC fabric with explicit authority propagation is more engineering than letting agents share context, and adds per-message latency.
- Authority-preserving delegation needs a concrete authority representation flowing through the channel; designing it so authority attenuates (never amplifies) across hops is non-trivial.
- Multi-agent workflows that assume shared state must be refactored to pass state through mediated, authorized messages.

### Residual risks the OS cannot touch

- **Authority re-aggregation across a delegation chain.** Even with per-hop checks, a sequence of individually-authorized delegations can compose into an effective authority no single agent was granted; the kernel mediates each message but cannot decide that the *chain's* aggregate intent is illegitimate [#25]. This is the multi-agent face of the unsolved intent-derivation problem [#24].
- **The hijacked-but-authorized delegation.** Once a cross-agent request is legitimately authorized, mediation must pass it; semantic "should this agent have asked that" is not lowerable to the kernel [#24][#14].

## Implementation status

The delegation-chain half of this topology is shipped (ADR-0006/0015 delegation via the uid-0 broker), and its **resource-authority re-aggregation bound is live-proven** (`make verify-agent-orch`, ARM CHAIN, 2026-06-15) — directly answering open question (2) below (yes, bulkhead enforces both):

- **Transitive narrow-never-widen.** Every hop's egress manifest is `parent ∩ requested`, where the parent mask is the kernel-attested *live* mask at that hop (`src/collector/broker.go`). So a grandchild's authority ⊆ child's ⊆ root's, and a chain's aggregate **resource** authority can never exceed the root's. Live-proven: a parent that HOLDS public delegates a child narrowed to `loopback,other`, which delegates a grandchild *requesting* public — the grandchild is born `loopback,other` (public AND-cleared by the *child's* mask, not the parent's) and its public fetch is E2-denied.
- **Generation depth cap.** `maxDelegateDepth` bounds chain height; the generation is derived ONLY from the kernel-attested parent instance name, never agent-supplied, so a child cannot reset its counter. Live-proven: the grandchild's signed delegate record binds `gen=2`. Children are `NO_EXPAND` (cannot self-widen) and may `ALLOW_DELEGATE` only a *narrower* grandchild.

This bounds **resource** re-aggregation structurally. The "Authority re-aggregation across a delegation chain" residual above is specifically the chain's aggregate **intent** being illegitimate even when every hop is individually resource-authorized — that remains a model-layer problem the OS cannot decide, correctly un-fixed.

**Post-ship security review (2026-06-16) — R2.** The "Children are `NO_EXPAND`" claim above had a
wiring gap: `NO_EXPAND` was enforced only as an `Environment=` flag inside the UNTRUSTED agent
runtime, which a compromised child bypasses by exec'ing `bulkhead-collector expand` (or writing
`EXPAND` to the broker socket) directly. The broker's `handleExpandTail` now refuses `EXPAND` from
any child whose kernel-attested cgroup path has delegation generation > 0 — the same un-spoofable
signal the depth cap trusts — so the self-widen cap is enforced in the TCB, not the jail. Unit-tested
(`TestExpandRefusedForDelegatedChild`) + no-regression on `make verify-agent-orch`. Record:
`docs/security-reviews/2026-06-shipped-isolation-review.md`.

## Confidence & open questions

Moderate-to-high on the topology decision; the underlying report verified 26/31 claims [#25], lower than most of the corpus, so the delegation-attack taxonomy is solid but not exhaustively sourced. Open questions: (1) the concrete authority token format and its attenuation semantics across hops; (2) whether bulkhead enforces a maximum delegation depth or per-chain authority budget to bound re-aggregation, given the OS cannot decide it semantically; (3) how mediated IPC interacts with the quarantine boundary of ADR-0036 when a quarantined (Q-LLM) agent delegates.

## Evidence (source reports)

- [#25] Multi-agent attack surface: injection laundering & delegation — primary basis; injection laundering, cross-agent privilege escalation, transport-only A2A identity, authority re-aggregation residual.
- [#24] Capability auth vs the agent confused-deputy — intent-derivation oracle is unsolved; authority context is lost across delegation chains.
- [#14] Agent threat matrix: what the OS can enforce — hijacked-but-authorized action survives any sandbox.
- [#16] When pushing safety into the OS actually wins — altitude framework placing cross-agent isolation at the right layer.

## Related ADRs

- ADR-0035 (resource authorization) — each mediated delegation is subject to the same default-deny check; multi-agent does not relax it.
- ADR-0031 / ADR-0032 (isolation substrate, interception primitive) — each agent domain reuses the same separate-kernel boundary.
- ADR-0034 (structural egress) — per-domain egress mediation applies independently to each agent; cross-domain traffic is not an egress bypass.
- ADR-0036 (model routing / quarantine) — delegation from or to a quarantined agent must not exfiltrate authority around the quarantine boundary.

---
*Evidence tags `[#N]` reference the bulkhead deep-research corpus (47 adversarially-verified reports) and `BULKHEAD-DESIGN-BRIEF.md`, kept in the design workspace alongside this repo.*
