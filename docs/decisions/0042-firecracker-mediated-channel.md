# ADR-0042: The Firecracker hostile-tier mediated channel (vsock legs, no direct network)

Status: Accepted (design + slices 1–2 live-proven 2026-06-17). Slice 1 (`make verify-firecracker-legs`, 8/8): a no-network microVM reaches a host endpoint ONLY through a provisioned vsock leg, an unprovisioned port is refused, no NIC. Slice 2 (`make verify-firecracker-agent`): the UNCHANGED `bulkhead-agent` probe in the microVM gets NOROUTE + ISOLATED + PROXY-OK through its UNIX leg → in-guest forwarder → vsock → host mux (the agent binary is byte-identical across tiers). Slice 3 (`make verify-firecracker-proxy`): the REAL egress proxy's allowlist (PROXY-OK + PROXY-DENY) + its signed chain (`verify-audit` passes) hold unchanged over the vsock transport. Slice 4 (`make verify-firecracker-jail`): the running firecracker holds no host internet socket, the per-instance dir holds exactly the 3 sockets, and the mux is their sole listener (the jailer mechanism is root-gated → slice 6). Slices 5–6 (in-image recipe → deployable jailer unit) pending; they need the owner sign-off below.
Date: 2026-06-17
Pillar: agent-isolation
Relates to: ADR-0031 (the hostile tier = reused Firecracker microVM; this is its mediated-channel realization, mirroring the runsc `--host-uds` legs), ADR-0033 (io_uring banned in the guest kernel + denied on the host bridge), ADR-0034 (the host egress proxy/router are the single mediated chokepoint this channel feeds), ADR-0040/0041 (the audit-chain + collector hardening the proxy/router carry, unmodified).

## Context and problem statement

The hostile tier (ADR-0031) runs an agent inside a Firecracker microVM — a separate guest kernel (host-surface collapse, spiked GO 2026-06-17, `fc-spike-check.sh`). The tier's invariant is the same as every other tier's, enforced one layer lower: the agent has **no direct network**, and its ONLY way out is the SAME mediated path — the host egress proxy (`/run/bulkhead-egress/egress.sock`) and model router (`/run/bulkhead-router/router.sock`), which enforce ADR-0034 policy and sign the audit chain. The design question: how does an agent *inside* the VM reach those host UNIX sockets, soundly, when Firecracker's only host↔guest channel is virtio-vsock — without giving a compromised in-VM agent any path to the host beyond those two endpoints, and ideally without changing the agent binary?

A 4-design panel + 3 adversarial lenses (with live vsock experiments on the build host) settled it. The adversarial pass found a real break (below) that reshaped the design.

## Decision

**Agent-unchanged vsock legs + a per-instance host mux; proxy/router unmodified.** Three byte-transparent hops per leg:

```
agent  net.Dial("unix", $BULKHEAD_EGRESS_SOCK)            [in guest, UNCHANGED binary]
  -> bulkhead-vsock-legs (in-guest forwarder)             : accept UNIX, AF_VSOCK connect(host CID 2, port 2222), splice
  -> firecracker virtio-vsock                             : guest->host surfaces as FC connecting INTO host "<uds-base>_2222"
  -> bulkhead-fc-vsockmux serve-host (per-instance, host)  : accept on <uds-base>_2222, dial /run/bulkhead-egress/egress.sock, splice
  -> egress-proxy (UNMODIFIED)                             : ADR-0034 allowlist / host-DNS / internal-IP-deny / MITM / signed chain
```

Router leg identical on guest port 2223 → `<uds-base>_2223` → the router UDS. Guest ports are fixed constants (2222 egress / 2223 router); the guest_cid is per-instance (≥3) but the guest always targets host CID 2, so isolation comes from the **distinct per-instance `uds_path` in a per-instance dir**, not from CID/port uniqueness.

- **Agent binary UNCHANGED across tiers.** It always `net.Dial("unix", …)` its legs from `BULKHEAD_EGRESS_SOCK`/`BULKHEAD_ROUTER_UDS`; the substrate supplies the sockets — the runsc `--host-uds=open` precedent. (Rejected: a vsock-native agent — `net.FileConn` rejects AF_VSOCK fds, and the agent module is vendor-free, so it would mean permanent raw-syscall, outside-the-netpoller code in the shared binary.)
- **The mux is transport-only.** `bulkhead-fc-vsockmux` does a byte-transparent splice — no HTTP/CONNECT parsing, and it NEVER derives a dial target from guest bytes (the port→target table is fixed by the launcher). So the leg is byte-equivalent to a runsc `--host-uds` leg and the proxy's single-canonical-parse guarantee is untouched.
- **No virtio-net.** The per-instance Firecracker config OMITS the network-interfaces stanza entirely, so the guest has no NIC, no route, no resolver — no interface to send a packet out of. The vsock device is a point-to-point pipe to the host's Firecracker process, not a network.

## Why no-direct-network holds (and the break that shaped it)

A guest AF_VSOCK connect to (host CID 2, port P) makes Firecracker connect INTO a host listener at `<uds-base>_<P>`; a port with no pre-bound listener is **refused** (live-confirmed: ECONNRESET on an unprovisioned port, and the guest has no NIC — `fc-legs-check.sh` slice 1). So the reachable set is structurally the ports we provision (2222/2223) and nothing else.

**The adversarial break (channel-confusion lens), and the control it forced.** Firecracker resolves `<uds-base>_<P>` LAZILY at connect time and FOLLOWS SYMLINKS. So the invariant does NOT rest on "unprovisioned ports reset" — it rests on the per-instance dir containing EXACTLY `{vsock.uds, vsock.uds_2222, vsock.uds_2223}`, all owned by the per-instance uid, with no other `<base>_<digits>` socket and no symlink. Otherwise a post-VMM-escape attacker at the Firecracker uid could pre-plant a symlink/stale socket that redirects a leg to an arbitrary host socket (the collector control socket, dbus, …). This is therefore a **LOAD-BEARING control**, not incidental hardening:

- The mux REFUSES to bind a leg path that is a symlink or non-socket (O_NOFOLLOW-equivalent; unit-tested `TestListenLegRefusesSymlink`).
- The launcher gives the mux a FRESH, EMPTY per-instance dir (`RuntimeDirectory` mode 0700) of which it is the sole writer; ExecStopPost unlinks `vsock.uds` and every `<base>_*` before the dir can be reused.
- A verify-time + runtime assertion (slice 4) that the dir holds exactly those three sockets and the mux is the sole listener.

## Other must-fixes from the adversarial pass

- **Connection-flood cap (load-bearing).** Firecracker imposes no cap; one compromised guest opened 1023 host-side connections. The mux enforces a per-leg concurrent-splice cap with fail-closed backpressure (`maxConnsPerLeg`), and the shared proxy/router need admission control, so one microVM can't egress-DoS the crown-jewel proxy (the R9 lesson, restated for this tier).
- **Host-side io_uring/AF_PACKET denial (the only plausible invariant break).** The HOST has a real network, so the mux AND the jailed Firecracker must deny io_uring BY NAME (not just `@aio`, which `@system-service` permits — the io-uring-jail-deny lesson), hold no AF_INET/AF_INET6/AF_PACKET socket, no CAP_NET_RAW/CAP_NET_ADMIN, and run in an empty no-route netns. A host-side raw-IO/io_uring path would bypass the proxy entirely.
- **Half-close correctness.** Both the in-guest forwarder and the host mux do per-direction CloseWrite, so a naive close-both-on-first-EOF can't truncate the proxy's OK/relay or the router's HTTP response (unit-tested `TestSpliceHalfClose`).
- **No-NIC is the device-model control, not the kernel** (the guest kernel ships `CONFIG_VIRTIO_NET=y`): a config-lint asserts every rendered Firecracker config has zero network-interfaces stanzas; owner-sign-off to drop `CONFIG_VIRTIO_NET` in the FC-tuned kernel as defense-in-depth.
- **Jailer.** Run Firecracker under its jailer (per-instance uid/gid, chroot, empty netns, new pid-ns, cgroup mem/cpu/pids limits) — the confinement of the VMM, which is itself the residual-risk component. Prefer distinct cooperating uids for mux vs Firecracker so a VMM escape doesn't inherit the mux's open proxy/router fds.

## Implementation slices (each live-verifiable host-side; the qemu suite has no nested KVM)

1. **(DONE, live-proven)** the mux (`src/fc-vsockmux`, serve-host/probe/nonic/stub modes) + `scripts/fc-legs-check.sh` (`make verify-firecracker-legs`): no-network microVM reaches the host endpoint only via the provisioned leg, unprovisioned port refused, no NIC. 8/8.
2. **(DONE, live-proven)** the in-guest forwarder (`fc-vsockmux serve-guest`) presenting the agent's UNIX legs + the UNCHANGED `bulkhead-agent probe-egress` (`scripts/fc-agent-check.sh`): NOROUTE + ISOLATED + PROXY-OK through the leg→forwarder→vsock→mux. The guest init must mount `devtmpfs` on /dev — busybox backgrounds a job's stdin from `/dev/null`, so a minimal rootfs without it silently fails to start the forwarder (a lesson for the slice-6 production guest init).
3. **(DONE, live-proven)** swap the stub for the REAL `bulkhead-egress-proxy` on a host UNIX socket (loopback allowlist + signed chain), mux leg → it (`scripts/fc-proxy-check.sh`, `make verify-firecracker-proxy`): the unchanged agent's PROXY-OK (allowlisted, reachable) + PROXY-DENY (non-allowlisted, refused by the real allowlist) hold over the vsock transport, the proxy SIGNED both decisions into its chain (0→3), and `bulkhead-collector verify-audit` PASSES (domain=egress-proxy) — ADR-0034 policy + the signed chain are byte-for-byte the same records the other tiers produce. (The full TLS-fetch-returns-200 + a router-FINAL leg reuse the same transport + the verify-egress-mitm mockchat; folded into the slice-6 end-to-end run rather than re-plumbed here.)
4. **(confinement assertions DONE, live-proven; jailer mechanism root-gated → slice 6)** `scripts/fc-jail-check.sh` (`make verify-firecracker-jail`): on the running microVM + mux, asserts firecracker holds NO AF_INET/AF_INET6 socket (the adversarial pass's only plausible invariant break — refuted live), the per-instance dir holds EXACTLY {vsock.uds, _2222, _2223}, and the mux is their sole listener. The jailer (per-instance uid/chroot/empty-netns/cgroup) needs root, so its live run is gated (as root with `$JAILER` the check wraps firecracker under it; the socket assertions hold either way — no-inet is inherent to the no-net-stanza config). The deployable hardened mux unit + the jailer launcher land in slice 6.
5. **(in-image, build-verified)** the firecracker Yocto recipe (pinned static firecracker+jailer), the FC-tuned guest kernel (io_uring off; drop VIRTIO_NET pending sign-off) + minimal agent rootfs.
6. **(deployable)** `bulkhead-agent-firecracker-launch` (the `[A-Za-z0-9_-]` inst guard) + `bulkhead-agent-firecracker@.service` + the per-instance mux unit; a two-instance arm asserting cross-instance isolation.

## What needs owner sign-off before the in-image slices (4–6)

- The mux as a NEW host-side TCB component in the post-compromise blast radius (the ADR-0033 "mediation fabric" surface) + its hardening floor (transport-only, fixed targets, AF_UNIX-only, empty caps, io_uring-by-name + @raw-io denied, conn cap, Requires= the egress-proxy fail-closed gate). Fold its lifecycle into the jailer vs a separate per-instance unit.
- Running Firecracker under the jailer (operational complexity vs the spike's bare boot).
- Dropping `CONFIG_VIRTIO_NET` in the FC-tuned guest kernel; io_uring stays disabled per ADR-0033.
- The 0666 proxy/router UDS group-gating follow-up should include the per-instance mux/Firecracker uid.

## Residual risks the OS cannot touch

A Firecracker/KVM 0-day or CPU side-channel BENEATH the vsock device lands the attacker in the least-privileged jailed Firecracker process (per-instance uid, chroot, empty netns), not host root or the host network — ADR-0031 names and accepts this; this design minimizes the surface to VMM + virtio-vsock + two endpoints, and the jailer is what keeps a VMM escape from being a host-network escape. After a VMM escape the mux's hardening is void unless mux and Firecracker run as distinct uids (hence the sign-off item).

## Related ADRs

ADR-0031 (hostile tier), ADR-0033 (io_uring ban), ADR-0034 (the mediated proxy this feeds), ADR-0040/0041 (the chain + collector hardening, unmodified by this channel).
