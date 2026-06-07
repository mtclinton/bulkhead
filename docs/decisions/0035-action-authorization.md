# ADR-0035: Action authorization: OS resource mediation is the guarantee; semantic tool-call auth is not lowerable; MCP servers are untrusted

Status: Proposed
Date: 2026-06-07
Pillar: action-authorization
Relates to: ADR-0031 (substrate it rides on), ADR-0034 (egress = its network half), ADR-0036 (routing quarantine gate), ADR-0037 (multi-agent domains); relates to ADR-0004 (BPF-LSM enforce) and ADR-0005 (agent jail runner).

## Context and problem statement

Bulkhead's thesis is "action authorization as an OS-level guarantee." That phrase conceals two different problems with opposite tractability. **Resource authorization** — which syscalls, network destinations, and files an agent may touch — is a single-trace safety invariant the kernel can mediate completely and default-deny. **Semantic tool-call authorization** — "should this tool be called, with these arguments, given what the user actually wanted" — is an information-flow / intent-derivation problem. The central failure mode across every shipping agent stack is the LLM acting as a *confused deputy*: legitimately holding authority, then exercising it on behalf of injected instructions. We must decide which half bulkhead enforces at the kernel, what we refuse to claim, and how to treat MCP servers, which are the dominant source of injected tool metadata and output.

## Decision drivers

- The confused-deputy must be made *structurally* impossible where possible, not approved away by a tired human.
- We must not overclaim: marketing semantic auth as a kernel guarantee is a false-confidence failure mode [#16].
- MCP is spec-level unsafe (tool poisoning, rug pulls, cross-server shadowing, output injection); the protocol will not fix this for us [#7].
- The actual 2024–2026 breaks were egress/orchestrator failures, not kernel escapes — so authorization spend must match isolation spend [#26].

## Considered options

1. **Adopt a standard auth stack as the guarantee** (MCP OAuth, scoped tokens, "allowed tools," HITL, OPA/Cedar). *Rejected as the guarantee.* All enforce *above* the syscall layer and each ultimately trusts a model- or classifier-influenced decision; none stops the confused deputy [#17]. HITL is structurally weak — ~93% prompt-approval, experienced users auto-approve ~2x more (consent fatigue) [#17]. Useful as defense-in-depth, never the boundary.
2. **Lower semantic intent-binding to the kernel via capabilities** (CaMeL / AuthGraph / SEAgent: bind every action to re-validated user intent). *Rejected as a kernel guarantee.* Authorization theory is solved (Hardy 1988; *Capability Myths Demolished*) and these systems crush injection ASR — but every one concedes the **intent-derivation oracle is unsolved**: you cannot scope a capability to "what the user meant" without per-step confirmation or an injectable guess. Parameters known only after reading untrusted data and authority-losing delegation chains are the concrete breakpoints [#24][#13].
3. **Trust MCP servers as first-class components.** *Rejected.* Tool poisoning, rug pulls, shadowing, and output-borne injection are spec-level (~90% of tool-return injections succeeded against audited clients); the 2025-11-25 auth spec leaves authorization itself optional [#7].
4. **OS-mediated default-deny resource authorization + treat MCP servers as untrusted sandboxed code.** *Accepted.* Resource mediation is reference-monitor-enforceable and shippable; the spec's own one OS-routed mitigation for the full-privilege local server is "run sandboxed with minimal privileges" [#17].

## Decision

Bulkhead's authorization model is **two-layer**:

1. **Resource authorization at the OS is the product.** Every syscall, network, and file action the agent takes **will be** mediated **default-deny** behind the ADR-0031 isolation substrate — the **target** OS-level guarantee. It **supersedes** the shipped fail-OPEN / observe-default posture of ADR-0004 (which default-*allows* absent a manifest and never default-denies); until that substrate ships, this is roadmap, not the current enforcement.
2. **Every MCP server is untrusted, sandboxed code** living behind that same mediation, in its own isolation domain — no implicit trust from the protocol.
3. We will **not** market semantic tool-call authorization as a kernel guarantee. Capability/intent binding ships as above-the-kernel defense-in-depth only, clearly labeled as such.

## Consequences

### Positive

- Removes an entire class — unauthorized *resource* access — structurally, regardless of the model's decision [#17].
- MCP supply-chain attacks (poisoning, rug pulls, shadowing) are contained to a sandbox, not the agent's full privilege [#7].
- Honest scoping keeps us out of the "perfect enforcement of a wrong policy" trap [#16].

### Negative / costs

- Per-MCP-server sandboxing adds IPC mediation and process overhead versus in-process tools.
- Default-deny resource policy demands an enumerated capability surface per workload; misconfiguration surfaces as broken tools, not silent over-grant.
- Defense-in-depth intent binding adds latency/confirmations without a hard guarantee [#24].

### Residual risks the OS cannot touch

- **The hijacked-but-authorized action.** Once a tool call is legitimately authorized, a perfect syscall sandbox *must* allow it; indirect injection and the lethal trifecta are model-layer and provably not fixable at the syscall layer [#14][#24].
- **Intent-derivation.** No capability system can scope authority to "what the user meant" without per-step confirmation or an injectable guess [#24].
- **Authority re-aggregation across delegation chains** in multi-agent flows — injection laundering, cross-agent escalation; A2A identity is transport-only [#25]. *This residual is owned by ADR-0037; see there for the decision.*

## Confidence & open questions

High confidence that resource authorization is the right altitude and that semantic auth is not lowerable [#16][#17][#24]. Open: how aggressively to require per-step confirmation on parameters derived from untrusted data without inducing the same consent fatigue that defeats HITL [#24]; how to mediate MCP-server-to-server IPC while preserving authority [#25].

## Evidence (source reports)

- [#17] Can action-authorization move to the OS layer (standards sit above syscalls; OS controls are the only structural stop)
- [#24] Capability auth vs the agent confused-deputy (theory solved, intent oracle unsolved)
- [#13] Object-capability security as the prompt-injection fix (ocap bounds reach, but the LLM-as-deputy re-enters)
- [#7] MCP threat model: spec vs implementation flaws (poisoning, rug pulls, shadowing, output injection)
- [#14] Agent threat matrix: what the OS can and cannot enforce

## Related ADRs

- **ADR-0031** (isolation substrate) — the separate-kernel boundary that resource mediation rides on.
- **ADR-0033** (io_uring broker) — brokered async I/O flows through this default-deny resource-authorization layer.
- **ADR-0034** (egress as structural guarantee) — network resource authorization is the egress half of this decision; both are default-deny structural controls.
- **ADR-0036** (model routing) — the quarantine boundary that keeps untrusted content away from privileged tool capabilities this ADR mediates.
- **ADR-0037** (multi-agent isolation domains) — extends "MCP server = isolation domain" to each agent, addressing delegation-chain authority re-aggregation.

---
*Evidence tags `[#N]` reference the bulkhead deep-research corpus (47 adversarially-verified reports) and `BULKHEAD-DESIGN-BRIEF.md`, kept in the design workspace alongside this repo.*
