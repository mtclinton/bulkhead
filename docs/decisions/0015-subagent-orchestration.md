# ADR-0015: Sub-agent orchestration (model-driven, task-carrying, credential-channeled)

Status: Accepted
Date: 2026-06-03
Relates to: ADR-0006 (inter-agent egress delegation, narrow-never-widen), ADR-0007 (human
approval gate), ADR-0009 (EXPAND), ADR-0011 (one-shot grant), ADR-0012/0013 (TCB-context GC +
composed hardening), ADR-0014 (the real agent runtime). Adds NO BPF hook, map, or new broker
verb shape beyond a task tail; the twice-reviewed E0-E3 object is unchanged.

## Context

ADR-0006 lets a jailed parent ask the TCB broker to spawn a child whose egress = parent ∩
requested. ADR-0014 landed the real `bulkhead-agent` runtime but a broker-minted child still
runs the template stub `bulkhead-agent-run` and is given NO `BULKHEAD_AGENT_TASK`, so a child
running the real runtime would `log.Fatalf("task empty")`. The multi-agent payoff the whole
architecture was built for — a REAL model-driven parent spawning a CHILD AGENT that runs a real
sub-task, kernel-confined to parent ∩ requested and audited per-child — is therefore not yet
realized. This slice closes that gap, driven by a real agent decision rather than a shell stub.

The security-critical question is the CHILD TASK SOURCE. A FIXED broker-side task has zero
attacker bytes but reduces the parent to deciding only whether/with-what-classes to delegate, not
what the child does — a strictly weaker demo than the thesis. A PARENT-SUPPLIED task is the
richer orchestration, but if the broker wrote that attacker-controlled string into the child
systemd drop-in, a `\n` + `ExecStartPre=...` payload would inject a unit directive = privilege
escalation. We choose parent-supplied, and close the injection threat by CHANNEL, not by
elimination.

## Decision

1. **Wire/tool.** Extend the verb to `DELEGATE <suffix> <classes> [task...]` and the agent
   `delegate` tool to `delegate <suffix> <classes> [task...]` (first two `Fields`, rest is the
   task, passed to the collector as ONE argv element). Empty task is allowed and means the
   broker's benign default, so the @worker demo and a no-task model call still work. The
   narrow-never-widen AND, the uid-0 gate, `reverifyCgroup`, `maxPendingPar`, the GC, and the
   `ExecStopPost` clears are untouched — the task rides alongside and changes nothing about the
   authority math.

2. **Injection-safe channel — the task NEVER touches unit syntax.** The broker writes the
   sanitized task bytes to `/run/bulkhead/tasks/<instance>.task` (0640, under its existing
   `ReadWritePaths=/run/bulkhead`) and the drop-in gains TWO FIXED lines built only from the
   broker-minted instance name:
   `LoadCredential=agent-task:/run/bulkhead/tasks/<instance>.task` and
   `Environment=BULKHEAD_AGENT_TASK_CRED=agent-task`. PID 1 materializes the file into the
   child's `$CREDENTIALS_DIRECTORY/agent-task` as a 0400 ramfs entry owned by the child's
   DynamicUser uid, auto-torn-down with the unit. The child reads it as one opaque blob; the
   agent loop already treats the task as transcript text, so a hostile task can only waste
   bounded steps. The attacker string is therefore always file CONTENT, never unit grammar.
   Defense-in-depth: `validTask` rejects NUL/control chars and any byte outside 0x20..0x7e and
   caps length at 4096, fail-closed BEFORE `register()` — a hostile task creates no child, no
   cgroup, no `.task` file.

   *Why a credential, not Environment= or a plain agent-read file.* Environment= reintroduces a
   quoting/escaping surface. A plain `/run/bulkhead/tasks/<inst>.task` exposed to the child via a
   path env would be world-readable 0644 and depend on a GC sweep for cleanup (an info-leak
   across recycled instance names). The credential is uid-scoped 0400, needs no extra agent
   `ReadWritePath`, and is reaped with the unit — it mirrors the existing audit-seed credential
   pattern.

3. **The child runs the REAL runtime.** A broker-minted child today runs the stub
   `bulkhead-agent-run`; only @worker overrides `ExecStart`. So `launchChild` now writes, into
   the same fixed drop-in, `ExecStart=` + `ExecStart=/usr/bin/bulkhead-agent %i` (the @worker
   reset-then-set pattern) plus short `BULKHEAD_AGENT_DEADLINE`/`BULKHEAD_AGENT_MAX_STEPS`
   constants. The router URL is sourced from the broker's OWN env
   (`BULKHEAD_CHILD_ROUTER_URL`) and written only if set — never from the parent (no
   SSRF-via-inference); production children inherit the template default.

4. **Bounding.** `maxPendingPar=4` caps fan-out per node. A depth cap is added: the broker mints
   `d<gen+1>-<randHex8>-<suffix>` where `gen` is parsed from the kernel-ATTESTED parent instance
   name in `parentPath`, and `handleDelegateTail` rejects `gen+1 > BULKHEAD_MAX_DELEGATE_DEPTH`
   (default 3) before `register()`. Depth is never read from anything the agent sends; a child
   cannot reset its own counter. The instance format changes from ADR-0006's `d-<hex>-<suffix>`
   to `d<gen>-<hex>-<suffix>` (harness greps for the literal `d-` prefix must be updated).

5. **Audit.** Each child cgroup has its own `bpf_get_current_cgroup_id`, so its socket_connect /
   grant verdicts land under its distinct cgid in the collector chain. The broker's signed
   delegate record (`recordDecision`) ties child<-parent and is extended with `gen=<N>` and
   `task_sha=<hex8 of sha256(task)>` (binds the exact bytes that ran without logging attacker
   text). `listPending`'s delegate row gains a sanitized, truncated `task="…"` preview so the
   operator approves with full context. An operator walks parent->child->grandchild by joining
   `record.comm` (child instance) to the child cgroup path; each level's own delegate record
   carries its attested cgid as the next edge.

The child stays OUTSIDE the TCB — DynamicUser, empty caps, `@system-service`, born one rung lower
in authority. No new BPF, no new map, the verified E0-E3 object unchanged.

## Verification

HOST go-tests: `TestValidTask` (accept clean ASCII + empty; reject NUL/control/`>0x7e`/over-cap),
`TestDelegatedDropInNoTaskBytes` (a hostile task never appears in the `.conf`),
`TestDelegGen`/`TestDelegateDepthCap`, `TestParseDelegateTail`, and src/agent
`TestTaskFromCredential`/`TestDelegateToolCarriesTask`. The register/resolve/flood/reverify/expand
tests are reused verbatim (the gate is untouched).

QEMU (`scripts/qemu-agent-orch-check.py`, mirroring `qemu-egress-check.py` + the parentP/parentQ
pattern): ARM ORCH-CONFINE — a mock-driven PARENT (manifest `loopback,other`, NO public) DECIDES
via its model loop to delegate a child requesting `public,...` with a task ordering a public
fetch; operator auto-approves; the child's manifest is `loopback,other` (public AND-cleared) and
its public fetch is E2-DENIED under the child's own cgid even though the task demanded it
(narrow-never-widen from a real agent), while its loopback inference and a FINAL prove the task
ran. ARM ORCH-ALLOW — a public-holding parent delegates the same and the child's public fetch
SUCCEEDS (the mask, not a blanket block). ARM ORCH-INJECTION — a control-char task returns
ERR bad-task with no child/cgroup/`.task`/`/run/pwned`; a sanitizer-passing directive-looking
task launches a DynamicUser child with no injected directive and the text lands only in
`$CREDENTIALS_DIRECTORY/agent-task`. ARM DEPTH-CAP — delegation succeeds to the depth cap then
ERR too-deep. AUDIT — `verify-audit` over both chains exits 0; the broker record names
parentCgID + child instance + gen + task_sha + operator. Regression — all existing arms and the
@worker ADR-0014 arm pass; broker-minted children now run the real runtime, so the legacy
@parentP/@parentQ stub-delegation arms' child-side assertion moves from a curl exit code to the
real-agent E2 observation.

## Seam

The native in-process broker client (sharing a wire package with the collector, replacing the
os/exec coupling) remains an ADR-0014 deferral. A TTL/GC sweep of `/run/bulkhead/tasks/*.task`
for any instance whose cgroup is gone is a follow-up (the credential copy is already ephemeral;
only the small broker-owned source file lingers). A per-deployment task grammar / structured
sub-task object (vs free text) and forwarding a child's escalation context up to the parent's
transcript are future slices. The E0 + delegation path (broker writes the child entry from its
own TCB context) remains the ADR-0006 stated seam.