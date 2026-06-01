# ADR-0005: Agent jail runner (multi-agent MVP)

Status: Accepted
Date: 2026-05-31
Relates to: ADR-0001 (decision #7: custom ns+cgroup+seccomp agent jail), ADR-0004
(BPF-LSM enforce E0–E3, keyed on cgroup id)

## Context

The BPF-LSM enforce layer (ADR-0004) authorizes agent actions *per cgroup*: E1
(ptrace), E2 (egress class manifest), and E3 (setuid/capset) all key on
`bpf_get_current_cgroup_id()`. But until now there were no agent cgroups — those hooks
were verified against the console login-session cgroup. This ADR adds the runner that
launches agents into their own cgroups, so that per-agent enforcement becomes real.
It is the first slice of the deferred "multi-agent orchestration · delegation · approval
gate" line from ADR-0001; delegation and the approval gate are explicitly **not** built
here (see Seams).

## Decision

An agent is a **systemd template-unit instance**, `bulkhead-agent@<id>.service`, in a
dedicated `bulkhead-agent.slice`. No custom `clone()` supervisor and no container
runtime — systemd is PID-1 and already applies seccomp/Landlock/caps/namespaces; reusing
it is the minimal, auditable path consistent with "no container-runtime dependency."

1. **Distinct cgroup per agent.** systemd creates
   `/sys/fs/cgroup/bulkhead-agent.slice/bulkhead-agent@<id>.service` per instance before
   forking any exec phase, so each agent has a distinct cgroup directory inode == a
   distinct `bpf_get_current_cgroup_id()` == a distinct key in the E1/E2/E3 maps.
   (Verified on the build host: two instances → inodes 9325778 vs 9325821.)

2. **The floor at launch.** The unit carries the `bulkhead-selftest`/`llama-server`
   hardening profile verbatim and tightened: `DynamicUser`, `NoNewPrivileges`, empty
   `CapabilityBoundingSet=`, `ProtectSystem=strict`, `SystemCallFilter=@system-service`
   with `SystemCallErrorNumber=EPERM` (and a `~`-deny list), `RestrictNamespaces`,
   `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `RestrictSUIDSGID`, etc. The
   payload thus *physically cannot* `bpf()` (EPERM seccomp) or hold caps — which is what
   makes the next point safe.

3. **The race (manifest must exist before the first `connect()`), closed by exec
   ordering.** A `+`-prefixed `ExecStartPre` runs the trusted collector with full
   privileges (`+` restores caps for that one command, bypassing the unit's empty
   `CapabilityBoundingSet`, so it has `CAP_BPF` to write the pinned `egress_policy` map)
   **in this instance's own cgroup**, so `bulkhead-collector egress set self
   $BULKHEAD_AGENT_EGRESS` writes exactly the cgroup id the payload will run under.
   systemd runs `ExecStartPre` to completion and only forks `ExecStart` on exit 0 →
   strict happens-before, **no sleep, no poll**. If the write fails the unit fails and
   the payload never runs — **fail-closed**: an agent never launches *unrestricted*, it
   simply does not launch. `ExecStopPost=-+… egress clear self` drops the manifest on
   exit to close the cgroup-inode-reuse hole.

   This is closed by **construction (exec ordering)** — not by `IPAddressDeny`. The
   payload process does not exist during the "pre-manifest window," so nothing runnable
   ever observes an absent manifest.

4. **Coarse 2nd layer.** `bulkhead-agent.slice` sets `IPAddressDeny=any` +
   `IPAddressAllow=localhost` (systemd's cgroup/eBPF egress firewall) — independent
   defense-in-depth composing with the nftables host-wide floor and the BPF E2 class
   manifest. It is not load-bearing for the race.

5. **Arming stays opt-in.** `bulkhead-enforce-egress.service` (sibling of
   `bulkhead-enforce.service`) arms `enforce on socket_connect`; not auto-enabled, so the
   shipped image is default-observe per ADR-0004. The manifest is always *recorded*;
   it only *bites* when armed.

No new Go and no BPF change: the existing `egress set self` / `enforce on socket_connect`
CLI and the E2 map semantics are sufficient. The verified E0–E3 BPF object is unchanged.

## Verification

Two demo instances, `bulkhead-agent@agentA` (`public,loopback,other`) and
`bulkhead-agent@agentB` (`loopback,other`), each probe the same destinations. With E2
armed: A reaches `https://api.anthropic.com/` (host floor allows it via the dnsmasq
nftset, so success proves it is *not* the floor) while B's `connect()` to the same host
is denied (`curl` exit 7 == `connect()` EPERM); both reach `127.0.0.1` (loopback in both
manifests) — same destination, opposite verdict, decided solely by which cgroup's
manifest applied, plus a class-precise loopback control. The signed audit log carries a
`socket_connect`/allowed record for A's cgroup and a `socket_connect`/denied/enforce
record for B's — one hook, opposite verdicts, different cgroups. This is the ADR-0004 E2
proof, now driven through two real per-agent jails instead of one console cgroup.

## Seams for later (documented, not built)

- **Inter-agent capability delegation.** The manifest source is already indirected
  (`$BULKHEAD_AGENT_EGRESS` / a drop-in). A TCB broker computes `child.mask =
  parent.mask ∩ requested` and calls the *same* `egress set <child-cgroup>` — no new
  map, no new hook. "Can only narrow, never widen" already lives in E3's `enforce_gain`;
  the collector being the sole privileged map-writer (agents can't `bpf()`) is exactly
  the trust boundary delegation needs.
- **Human approval gate.** The `+ExecStartPre` is already a synchronous, fail-closed
  admission point. An earlier `ExecStartPre`/`ExecCondition` (`bulkhead-approve %i …`)
  that blocks on operator ack over the tailnet and exits non-zero on denial slots in with
  the same happens-before primitive, no polling. The signed provenance log is the audit
  substrate the approval UI reads/writes.
- **E0 + E2 together (the one real limitation).** The `+ExecStartPre` runs in the
  agent's *non-TCB* cgroup; E0 (`enforce on bpf`) keys on cgroup id, not caps, so with
  E0 armed the pre-step's `bpf()` write would be `-EPERM`'d. To run E0 *and* per-agent
  egress, the manifest writer must run from a TCB cgroup (e.g. `systemd-run
  --slice=system.slice --scope …` ordered `Before=` the agent's `ExecStart`, or fold the
  write into the collector's own TCB context). For this MVP, E2 is the target and E0
  stays opt-in/off (its ADR-0004 default), so the in-unit `+ExecStartPre` is correct and
  shippable today.

All three slices share one substrate — per-cgroup BPF maps keyed on
`bpf_get_current_cgroup_id()` + systemd `ExecStartPre` ordering — so later slices add
units/CLI verbs, never a new enforcement layer, and never require re-verifying the
E0–E3 BPF object.
