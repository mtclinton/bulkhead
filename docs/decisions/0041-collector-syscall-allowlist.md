# ADR-0041: Default-deny syscall allowlist for the privileged collector

Status: Accepted — shipped + live-proven on the production image (2026-06-17, `make verify-attest` ALL PASS: the collector came up `active` under the allowlist, did `bpf()` map reads live under armed-E0, signed the chain HEADs, and the box reached the enforcing-TCB state / PCR-14 quote — with no systemd filter-parse warning)
Date: 2026-06-17
Pillar: action-authorization (the TCB)
Relates to: ADR-0033 (io_uring banned from the substrate; this preserves that for the collector), ADR-0016 (the collector hosts the control-socket bpf()-write chokepoint), ADR-0011/0012 (the broker / SO_PEERPIDFD attestation), ADR-0008/0025 (the audit-signing seed the collector holds).

## Context and problem statement

bulkhead's thesis is that a small, hardened TCB holds even when an agent is fully compromised. Every agent jail and even the boot gate runs under a **default-deny** seccomp allowlist (`@system-service` + a few explicit extras). The privileged **collector** — the single most powerful process in the system: it owns the eBPF path (loads the LSM programs, owns the maps), hosts the broker and the SO_PEERPIDFD cgroup attestation, and holds the audit-signing seed — was the one TCB component still running under a permissive **group-denylist** (`~io_uring… @swap @reboot @module @raw-io @clock @cpu-emulation @obsolete @mount`). A denylist allows everything not named — including future syscalls and the entire long tail the collector never uses — so a collector compromise had a far wider syscall surface than the rest of the system. The unit comment had deferred the allowlist "once that set is strace-verified," because a missing syscall fails the collector closed and takes the whole E0/E2 enforcement floor down with it.

## Decision

Replace the denylist with a tight allowlist:

```
SystemCallFilter=@system-service bpf perf_event_open
SystemCallErrorNumber=EPERM
```

- **`@system-service`** is the default-deny base. It covers the Go runtime, file I/O, the AF_UNIX/AF_NETLINK sockets, `epoll`/`mmap` for the ringbuf, `getsockopt` for SO_PEERPIDFD, and the `/proc/<pid>/fdinfo`+`/proc/<pid>/cgroup` reads behind the pidfd cgroup attestation.
- **`bpf`** — every eBPF operation: `BPF_PROG_LOAD`, `BPF_MAP_*`, and the `BPF_LINK_CREATE` of the five LSM attaches, plus the control-socket map writes. Gated by CAP_BPF.
- **`perf_event_open`** — defensive: the cilium/ebpf loader feature-probes with it on some kernels. The LSM links themselves are `BPF_LINK_CREATE`, not perf events; gated by CAP_PERFMON.

Everything else the old denylist named is denied for free, because none of `io_uring_*`, `@swap`, `@reboot`, `@module`, `@raw-io`, `@mount`, or the `@clock` setters are in `@system-service`. **The load-bearing io_uring ban is preserved**: an io_uring ring is a syscall-invisible I/O channel (shared SQ/CQ rings) the provenance collector must never be able to open, and the allowlist denies it without naming it.

`SystemCallErrorNumber=EPERM` (not the default kill) keeps a denied call a handled error rather than a SIGSYS crash of the TCB.

## Verification

The set is **verified by running the real collector under it and passing the full live suite** — empirical proof of functional sufficiency, stronger than a static strace (which shows attempts, not success): `verify-floor` exercises BPF load + the 5 LSM attaches + all four enforce hooks + the ringbuf + the control-socket map writes; `verify-agent-orch` exercises the broker delegation + SO_PEERPIDFD cgroup attestation; `verify-attest` exercises the Ed25519 signing path + the TPM-quoted chain HEADs. A missing syscall surfaces as a cilium/ebpf error naming the failed operation in the journal, so any gap is diagnosable without a tracer.

## Consequences

### Positive
- The crown-jewel TCB process now has the same default-deny syscall posture as the rest of the system; a collector compromise is confined to its actual ~needed set instead of "everything but a few groups".
- The io_uring ban and all the old denylist's group denials are preserved (and extended — the long tail is now denied too).

### Negative / residual
- A syscall used only in a path no verify target exercises (a rare error path, a specific GC reclaim) could return EPERM and degrade that path. Mitigated by `@system-service` being the conservative, well-tested baseline for service runtime/IO/socket needs, by EPERM (not kill) keeping the collector alive, and by the cilium/ebpf errors making any field gap diagnosable. A literal strace capture across every code path remains a possible follow-up if a gap ever appears.

## Related ADRs

ADR-0033 (io_uring substrate ban, preserved here), ADR-0030/0039 (the other hardening ADRs this follows in form).
