# ADR-0014: Agent runtime (the real jailed tool-using agent)

Status: Accepted
Date: 2026-06-03
Relates to: ADR-0001 (multi-agent orchestration line), ADR-0002 (OpenAI-compatible router + the
free/paid routing gate), ADR-0004 (BPF-LSM E0–E3 + the TCB model), ADR-0005 (agent jail runner and
the "the real agent runtime replaces this later" seam), ADR-0006/0007 (delegation broker + human
approval gate), ADR-0009 (operator-approved egress expansion), ADR-0011 (one-shot E1/E3 grant),
ADR-0012/0013 (TCB-context GC + composed-system hardening). Adds NO BPF hook, map, or broker verb;
the twice-reviewed E0–E3 object is unchanged.

## Context

Every bulkhead security primitive — per-agent jails, BPF-LSM E0–E3 enforce, the capability-caged
TCB broker, the signed audit chains, the nftables egress floor, the router — is today exercised only
by DEMO STUBS. `bulkhead-agent@.service` literally `ExecStart=/usr/bin/bulkhead-agent-run %i`, a
shell probe loop, and ADR-0005 explicitly left the runtime as a documented seam: "the real agent
runtime replaces this later." This slice closes that gap with a MINIMAL-BUT-REAL tool-using agent
that runs INSIDE a bulkhead jail, does inference via the router, uses a small real tool set, and
escalates to the broker when its jail denies an action — so the whole stack is validated against a
real workload. The deliverable is not "an agent that works" but a runtime whose EVERY action is
provably confined (kernel E2) or authorized (human-gated broker) and non-repudiably recorded.

## Decision

1. **Component.** A new `src/agent` Go module (`github.com/mtclinton/bulkhead/agent`, go 1.22, pure
   stdlib, CGO off — no `ebpf`/`x/sys` import, so it can never touch a pinned map), built into a
   single static binary `bulkhead-agent` by a Yocto recipe `bulkhead-agent_0.1.0.bb` cloned
   byte-for-byte from `bulkhead-router_0.1.0.bb` (same shared `SRCREV`), and a Buildroot prototype
   `external/package/bulkhead-agent/` cloned from `bulkhead-router/`. `bulkhead-units` RDEPENDS gains
   `bulkhead-agent`.

2. **The seam.** Exactly ONE line changes in `bulkhead-agent@.service`:
   `ExecStart=/usr/bin/bulkhead-agent %i` replaces the stub. The `+ExecStartPre` privileged manifest
   write, the DynamicUser/empty-caps/`@system-service`/`ProtectSystem=strict` floor, the
   `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, and both `ExecStopPost` clears are inherited
   verbatim — the runtime is born into the proven jail. The shell stub `bulkhead-agent-run` and its
   demo drop-ins (@agentA/@agentB/@expander/@granter/@parentP/@parentQ/@narrowee/@grantholder) stay
   in tree so no existing E2/delegation/grant/narrow arm regresses; the runtime ships alongside as
   `bulkhead-agent@worker`.

3. **The loop.** Bounded perceive→decide→act. PERCEIVE: a transcript of a fixed system prompt
   (tool grammar + task) + `BULKHEAD_AGENT_TASK` + prior observations. DECIDE: POST
   `ChatRequest{Messages, Route:"local"}` to `BULKHEAD_ROUTER_URL` (default `127.0.0.1:8080`) and
   parse `Choices[0].Message.Content`. Forcing `route=local` makes the agent a free-tier workload by
   construction — the router's `decide()` ignores a client-forced `RouteAPI`, so the agent can never
   drive denial-of-wallet. ACT: parse one directive, dispatch, append a truncated (~2KB) observation,
   loop. Terminate on `FINAL`, on the iteration cap (`BULKHEAD_AGENT_MAX_STEPS`, default 6), or on a
   wall-clock deadline (default 90s).

4. **Tool-call protocol — constrained text, NOT function-calling.** qwen2.5-3b-q4 emits `tool_calls`
   JSON unreliably and the router proxies llama-server bodies verbatim (no server-side grammar/tool
   enforcement to lean on). The model must emit one line `TOOL <name> <arg>` or `FINAL <text>`. The
   parser is tolerant-in / strict-out: first matching line wins, leading prose ignored, verb
   lower-cased, name checked against a fixed `map[string]Tool` allowlist, arg validated per-tool
   (`url.Parse` / class enum) and length-capped; a no-match feeds back a corrective observation that
   costs one step. **Security never depends on the model behaving** — a malformed or hostile reply
   just wastes a bounded iteration.

5. **Tool set (spans the gated surface).** `fetch <url>` — the E2-gated egress tool (no-redirect
   net/http GET, body-capped); a public host needs the `public` class the default `loopback,other`
   manifest omits, so with E2 armed `connect()` is EPERM'd and the tool returns a structured DENIED
   observation. `request_egress <classes>` — exec the existing `bulkhead-collector expand`, which
   dials the broker (class `other`) and BLOCKS for an operator; deny ⇒ the agent cannot proceed,
   allow ⇒ the cgroup's `public` bit flips and a retried fetch succeeds. `delegate <suffix>
   <classes>` — optional, exec `bulkhead-collector delegate` (narrow-never-widen sub-agent). The
   agent execs the audited verbs rather than reimplementing the wire protocol, so it adds ZERO new
   wire surface and stays out of the TCB; identity is kernel-attested by SO_PEERPIDFD. A one-shot
   grant is REQUEST-only — consuming ptrace/setuid/capset needs a `@system-service`-denied syscall,
   matching the grant-hold stub's stance.

6. **Inference in qemu, no LLM, no production special-casing.** The 256MB/CPU-only/no-model-disk
   harness cannot run llama-server. The agent's ONLY inference knob is `BULKHEAD_ROUTER_URL`;
   production points it at the router→llama-server, the cheap arm points it at a canned
   `/v1/chat/completions` responder. The mock is a `mockchat` SUB-COMMAND of the same binary
   (`bulkhead-agent mockchat`), run by a demo-only, NOT-`[Install]`-enabled
   `bulkhead-mockchat.service` on `127.0.0.1:8088`, returning scripted `ChatResponse` bodies keyed by
   the count of tool observations in the transcript (turn 1 `TOOL fetch https://api.anthropic.com/`,
   turn 2 after the deny `TOOL request_egress public`, turn 3 retried fetch / `FINAL`). The agent
   code is byte-identical in both paths — only the env URL differs, exactly the indirection the
   router uses for httptest. A real-model parseability claim is gated behind an optional
   4096MB+data-disk arm.

## Verification

HOST go-tests (`src/agent`, CGO off): parser table tests (TOOL/FINAL, first-valid-line-wins,
prose-padded, malformed→corrective, arg validators); loop tests against an httptest router (decide
order, observation truncation, max-steps/deadline/FINAL termination, error-fed-back-not-fatal); tool
tests (fetch success + connect-refused observation; `request_egress` with a PATH-shadowed fake
collector asserting OK→observation and non-zero→ESCALATION DENIED); a denial-of-wallet test asserting
the outbound request carries `route=local`; a contract test pinning the collector `OK `/`ERR `
prefixes.

QEMU arms (`scripts/qemu-agent-check.py`, mirroring `qemu-egress-check.py`; `make verify-agent`):
ARM A (cheap, mockchat) — a loopback fetch succeeds, FINAL reached, a `socket_connect`/allowed record
exists. ARM B-deny (the headline; E2 armed, manifest `loopback,other`) — `fetch
https://api.anthropic.com/` is EPERM'd by E2 (a `socket_connect`/denied/enforce record proves it is
E2, not the floor, which allows that host); the model decides `request_egress public`, the operator
runs `approve deny <id>`, the agent logs ESCALATION DENIED, the retried fetch is still EPERM, and an
`expand-egress`/deny record names the operator. ARM B-allow — `approve allow <id>` flips the
cgroup's `public` bit (visible in `status`), the retried fetch succeeds, the broker chain has
`expand-egress`/approve→`socket_connect`/allowed. AUDIT — `verify-audit` over both chains exits 0.
ARM C (optional, 4096MB+data-disk, real qwen) — assert only that the loop ran and reached a
parseable FINAL. Regression — the existing egress/m5 and all legacy demo arms pass unchanged (stub
retained).

## Seam

The agent is the FIRST occupant of the untrusted side of the E0–E3 boundary that is a real workload
rather than a probe. It adds no BPF, no map, no broker verb — it reuses the existing CLI verbs and
the proven jail. The `map[string]Tool` registry is the product-growth seam (one map entry per new
tool). Deferred: a llama.cpp GBNF grammar forwarded through the router to harden small-model protocol
adherence at the source (the router currently passes bodies untouched); consuming (not just
requesting) an E1/E3 grant inside an agent, which needs a narrowed per-instance seccomp relaxation
and is its own ADR; a native in-process broker client sharing a wire package with the collector,
replacing the os/exec coupling once the verbs stabilize.

## Confined-jail runtime (ADR-0034, live-verified 2026-06-10)

The same runtime now also runs inside the ADR-0034 **confined** jail (`bulkhead-agent-confined@`,
a no-route netns), not only the E2-gated `bulkhead-agent@`. There both of the agent's legs are
*structurally* mediated rather than policy-gated: the model leg dials the bind-mounted router UDS
(the netns has no other path to a model at all), and the web `fetch` tunnels through the host
egress proxy, which signs the ALLOW into its /data chain. `make verify-confined-agent` boots the
wic, points the router's local backend and the proxy allowlist at a loopback mockchat, runs the
confined agent on a `FETCH-ONLY` task, and asserts it reached FINAL with the fetch delivered HTTP
200 through the proxy and recorded as a fresh signed egress record. This closes the ADR-0034 inc1
follow-up that had the confined jail running only the `probe-egress` vehicle. No Go change: the
runtime, the router-UDS model leg, and the egress-proxy fetch leg (egress.go) already existed —
the jail just launches the real loop with a task instead of the probe.