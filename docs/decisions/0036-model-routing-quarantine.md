# ADR-0036: Model routing: ship only as a structural quarantine with deterministic non-LLM enforcement

Status: Proposed
Date: 2026-06-07
Pillar: model-routing
Relates to: ADR-0035 (resource-auth layer beneath the quarantine gate), ADR-0034 (same structural-not-policy principle), ADR-0031 (substrate), ADR-0037 (multi-agent); refines the model-routing pillar of ADR-0001.

## Context and problem statement

"Model routing as an OS-level guarantee" is the most overclaim-prone of bulkhead's three pillars. "Routing" can mean two structurally different things. One is a *quarantine*: an architectural boundary where the model that ingests untrusted content cannot, by construction, reach privileged tools (the Dual-LLM / CaMeL Q-LLM pattern). The other is *triage*: a learned or heuristic classifier that inspects content, guesses its sensitivity, and routes it to a more- or less-privileged model. These have opposite security properties, and the second one is routinely marketed as the first. We need to decide which — if either — bulkhead ships as a security control, and at what layer enforcement lives.

## Decision drivers

- A "boundary" enforced by a model's judgment is not a boundary; it is an injection target [#27].
- Heuristic triage routers are themselves prompt-injectable and drivable to ~100% misrouting in either direction; the 12 most recent triage-style defenses collapse to >90% ASR under adaptive attack after reporting near-zero ASR statically [#27].
- The only routing variant with a *provable* property — untrusted tool output cannot influence control flow — gets that property from a deterministic interpreter plus capability checks, not from the model [#2].
- The altitude test: this layer wins only as a single-trace, completely-mediatable structural invariant; as classifier triage it is the "perfect enforcement of a guessed/wrong policy" anti-pattern [#16].
- Do not let marketing imply a kernel guarantee the mechanism does not provide.

## Considered options

1. **Classifier / heuristic-triage routing as a security control.** Rejected. The router is a prompt-influenceable component on the trust path; adaptive attacks defeat the class (>90% ASR), and the router itself is steerable to ~100% in either direction [#27]. This is theater against a motivated adversary.
2. **LLM-judged quarantine** (a model decides whether the privileged path may be taken). Rejected. Same failure as triage — an LLM in the decision path is not a reference monitor; it is injectable [#27].
3. **Structural quarantine with deterministic non-LLM enforcement** (Q-LLM has no privileged-tool references by construction; the privileged path is gated by an interpreter + capability check the model cannot influence). **Accepted.** This is the only variant that adds real margin and the only one that survives the altitude test [#27][#16][#2].
4. **Ship no routing pillar.** Viable fallback. If bulkhead cannot make routing a non-LLM-enforced boundary, this is strictly preferred to shipping option 1 or 2 under a security label.

## Decision

Bulkhead will implement model routing **only** as a structural quarantine: the untrusted-content model holds no references to privileged tools, and every privileged action is gated by a **deterministic, non-LLM capability check** (an interpreter plus capability enforcement) that no model — quarantined or privileged — can influence. Bulkhead will **not** ship classifier/heuristic/LLM-judged triage as a security control, and will not market any model-mediated routing decision as a boundary. The product bar for this pillar is "structural quarantine or nothing": if a routing decision cannot be lowered to a non-LLM-enforced boundary, it is not sold as security.

## Consequences

### Positive

- The pillar's security claim becomes auditable: the boundary is a deterministic check, not model behavior [#27].
- Inherits the one provable property in the corpus — untrusted tool output cannot influence control flow — enforced by a deterministic **user-space interpreter**, not the model [#2]. This is an interpreter / control-flow-integrity property, **not itself a kernel reference-monitor guarantee**; it is layered on top of, and distinct from, the OS resource authorization of ADR-0035.
- Honest altitude placement; avoids the false-confidence failure mode [#16].

### Negative / costs

- Quarantine requires a plan-then-act decomposition (Q-LLM extracts data, deterministic layer enforces capabilities), which constrains agent design and adds engineering surface.
- The provable guarantee is **narrow and conditional**: it does not cover side channels, data-dependent control flow, a corrupted policy interpreter, a malicious initial prompt, or consent fatigue [#2].
- **Static plan-up-front quarantine cannot replan**: CaMeL collapses to 0% utility on the dynamic AgentDyn benchmark [#2]. Bulkhead must either accept reduced dynamism in the quarantined path or invest in a replanning-aware enforcement model — without reintroducing an LLM into the gate.

### Residual risks the OS cannot touch

- **Nothing extra is added by this design beyond the chosen enforcement** — but the guarantee holds **only** if enforcement stays non-LLM. The moment a model judges the route, the boundary is gone [#27].
- **Dynamic/open-ended replanning** defeats static structural defenses; the quarantine cannot cover workflows whose control flow depends on untrusted data read at runtime [#2].
- A **malicious initial prompt**, side channels, and consent fatigue sit outside the quarantine's provable envelope [#2].
- **CPU side-channels and hypervisor/KVM 0-days** sit beneath this quarantine as beneath every bulkhead boundary [#10][#36] — the same sub-boundary residual floor ADR-0031/0032/0033/0038 carry.
- This pillar does not rescue **intent-derivation** or the **hijacked-but-authorized action** — those remain model-layer problems no routing boundary fixes (see ADR-0035).

## Confidence & open questions

High confidence on the rejection of triage as a security control: the adaptive-attack collapse is directly evidenced and the routers' own injectability is verified [#27]. High confidence that the only defensible variant is non-LLM-enforced quarantine [#27][#2]. Open question: whether bulkhead can build a **replanning-capable** quarantine that keeps enforcement deterministic, given CaMeL's 0% dynamic-utility result [#2] — if not, the quarantined path is limited to static-plan workflows and the rest of the agent runs under the resource-authorization boundary alone.

## Evidence (source reports)

- [#27] Is security-relevant model routing real or theater — quarantine adds margin; triage routers are prompt-injectable and collapse (>90% adaptive ASR).
- [#2] Structural vs probabilistic prompt-injection defense — CaMeL's provable control-flow guarantee is real, narrow, conditional, and 0% on dynamic replanning.
- [#16] When pushing safety into the OS actually wins — altitude test; triage is "perfect enforcement of a guessed policy."

## Related ADRs

- **ADR-0035 (action authorization):** the quarantine gate is a deterministic *user-space* interpreter check layered **on top of** ADR-0035's kernel resource-authorization — related, but not the same layer; semantic intent remains unenforceable at the kernel in both.
- **ADR-0034 (egress):** structural-not-policy is the same design principle applied to the network path; both reject a model- or heuristic-mediated decision as the boundary.
- **ADR-0031 (isolation substrate):** the quarantined model runs as its own isolation domain; multi-agent delegation (ADR-0037) inherits the authority-preservation requirement.

---
*Evidence tags `[#N]` reference the bulkhead deep-research corpus (47 adversarially-verified reports) and `BULKHEAD-DESIGN-BRIEF.md`, kept in the design workspace alongside this repo.*
