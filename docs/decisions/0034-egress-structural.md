# ADR-0034: Network egress: structural confinement + mediating proxy, not allowlist-as-boundary

Status: Accepted — increment 1 (structural confinement) + increment 2 sub-A (selective TLS-termination + content inspection) shipped + live-verified; inc2 sub-B started (re-signing CA key TPM2-sealable on bare metal); sub-B remainder (rule-engine breadth, response inspection, HTTP/2, passthrough exception list) pending
Date: 2026-06-07

## Implementation status

**Increment 1 — structural confinement — SHIPPED + LIVE-VERIFIED (2026-06-07).** A new
`bulkhead-egress-proxy` (`src/proxy/`) is the single host-mediated egress path: one canonical
`CONNECT host:port` parse over a unix socket (closing the parser-differential class), host-side
DNS, an advisory allowlist, a post-resolution internal-IP deny (loopback/private/link-local/
metadata SSRF guard), and a bounded splice — adversarially reviewed and hardened (4 findings).
A new confined jail class `bulkhead-agent-confined@` runs the agent in a `PrivateNetwork=yes`
no-route netns whose only exits are the bind-mounted egress-proxy and router unix sockets;
the agent's web-fetch leg tunnels through the proxy and the model leg dials the router UDS.
`make verify-egress-proxy` boots the wic and asserts, from inside the jail, that direct egress
is impossible (no route / isolated loopback) and the proxy is the only — and a working —
path out, with non-allowlisted destinations refused. The shipped E2-gated `bulkhead-agent@`
class (ADR-0004) is unchanged; this lands the structural model alongside it, not as a rip-out.

**Increment 2 sub-A — selective TLS-termination + content inspection — SHIPPED + LIVE-VERIFIED
(2026-06-15).** The allowlist gained a per-entry mode token (`inspect` | `passthrough` | `pinned`,
default passthrough). For an `inspect`-marked host on a TLS port the proxy now TLS-TERMINATES: it
presents a leaf for the CONNECT host (never the SNI — preserving the single-canonical-parse
invariant) signed by a re-signing CA generated ON-DEVICE at first boot (`bulkhead-provision-mitm-ca`,
unique per appliance; key plaintext-on-`/data` in the VM phase, tpm2-sealed on bare metal in sub-B),
and re-originates TLS to the real upstream with FULL Web-PKI verification (the MITM never downgrades
the auth the agent gave up). The confined agent trusts the CA via a jail-scoped `SSL_CERT_FILE` bundle
(proxy CA ++ Web-PKI roots) — the host TCB services keep default trust, so the CA's blast radius is the
confined agent alone. Decrypted agent→upstream bytes pass a content hook (per-flow byte budget,
Host-vs-CONNECT coherence, an operator needle denylist); a deny drops mid-stream. Every inspected flow
signs a `Hook=inspect` record (method/host/path/size/verdict — never the body) and every non-terminated
flow a `Hook=passthrough` record, so the chain is an honest coverage ledger (`inspect` vs `passthrough`
counts = the body-inspected fraction). `make verify-egress-mitm` proves both arms end-to-end on a
loopback TLS upstream. NOTE: `default=passthrough` leaves the body-exfil gap OPEN for any allowed host
not explicitly marked `inspect` — the ledger makes that a measurable, budgeted decision, not a silent
erosion.

**Increment 2 sub-B — STARTED.** The re-signing CA key is now TPM2-sealable on bare metal: in a
`BULKHEAD_SEAL_KEY=tpm2` build the first-boot provision seals `ca.key` to a PCR-bound
`ca.key.cred` (systemd-creds, `--with-key=tpm2 --tpm2-pcrs=7`) and persists NO plaintext, and the
proxy loads it via `LoadCredentialEncrypted` — the same proven pattern as the audit seed, gated on
the same build switch (the public `ca.crt` stays plaintext). The plain (VM/dev) path is unchanged
and stays fully qemu-verified; the tpm2 unseal is bare-metal-authoritative (qemu vTPM sealing is
unreliable, ADR-0001 #12), and the tpm2-mode wiring is build-verified. The
`BULKHEAD_EGRESS_DEFAULT_MODE=inspect` high-assurance knob is now SHIPPED + live-verified: it flips
the disposition of UNMARKED allowlist entries from passthrough to inspect, so a tier can demand
"every allowed host is TLS-terminated + content-inspected, or denied if it can't be" (the natural
completion of the R4 inspect-fail-closed rule) with a single flag — an explicit per-entry mode still
overrides, and unset keeps the inc1-compatible passthrough default (`verify-egress-mitm` ARM 4).
The rule engine's first rule — an operator HTTP-method allowlist for inspected egress
(`BULKHEAD_EGRESS_INSPECT_METHODS`, e.g. `GET,HEAD`) — is now SHIPPED + live-verified: a terminated
request whose method is outside the allowlist is denied the moment its head parses, BEFORE the body
relays upstream (blocking e.g. a POST/PUT body-exfil to an otherwise-allowed inspected host), and
signed as a `Hook=inspect` deny (`reason=method:<m>`, `verify-egress-mitm` ARM 5; case-insensitive so
a lowercase method cannot dodge it). The MITM leaf-cert cache is also now bounded (a hard ceiling with
cheap re-mint on eviction). STILL PENDING: extending the rule engine to path/header allow-deny +
response-direction inspection + body DLP; HTTP/2 + websockets; the curated, audited pinned-cert/mTLS
passthrough exception list (the open question below); an audit-chain volume review.

**Post-ship security review (2026-06-16).** An adversarial review of the shipped egress boundary
closed two wiring gaps (record: `docs/security-reviews/2026-06-shipped-isolation-review.md`).
**R1** — the proxy now `Requires=` the fail-closed audit gate; it was only `Before=`-ordered after
the chain verifier, which does NOT propagate failure, so a forged `/data` chain refused the TCB
collector but still granted untrusted web egress. A tampered chain now fail-closes the proxy and
transitively every confined/runsc agent that `Requires=` it. **R4** — an `inspect`-marked host the
proxy cannot TLS-terminate (no re-signing CA loaded, or a non-TLS port) now DENIES instead of
silently splicing through uninspected; previously a failed CA load downgraded EVERY inspect host to
opaque passthrough. The disposition is decided before the dial, so the deny signs a single
`inspect-unavailable` record and never reaches upstream. Live-verified: `make verify-egress-gate`
(R1) and `make verify-egress-mitm` ARM 3 (R4); bundled into `make verify-security-review`.

Decided/known inc1 simplifications to revisit: the proxy & router UDS are `0666` (the agent
is a distinct DynamicUser; group-gating to a static `bulkhead-egress` group is a hardening
follow-up — the boundary is the netns, not the socket mode). Shipped since this ADR was first
written: proxy egress decisions are now folded into an Ed25519-signed, hash-chained provenance
log on `/data` under the `egress-proxy` audit domain (ADR-0017), verified at boot by the
collector's verify-audit gate and across an in-guest reboot by `make verify-egress-reboot`; and
`io_uring_setup` is now seccomp-denied in both agent jails per ADR-0033 (the confined probe's
`IOURING` check asserts the EPERM), closing a syscall-invisible I/O channel the inc1 jail
otherwise left reachable.

Pillar: egress (cross-cutting)
Relates to: ADR-0031 (substrate gives isolation, not egress), ADR-0033 (the same broker-don't-expose mediator pattern), ADR-0035 (egress is the network half of action authorization), ADR-0036 (routing relies on this egress boundary).
Supersedes-in-part: the shipped ADR-0006/0009/0010 egress line — its dnsmasq→nftset domain allowlist is exactly the name-matching policy this ADR classes as advisory, not a boundary; this ADR replaces it as the egress *guarantee* (the allowlist is retained only as an advisory hint).

## Context and problem statement

Egress is the agent-sandbox market's single weakest layer. Compute and filesystem isolation are largely solved; outbound network control is almost universally implemented as destination-domain allowlisting that never inspects traffic content and is therefore bypassable *by construction* [#15]. The disclosure record is unambiguous and recent: Claude Code shipped a SOCKS5 null-byte parser differential (`host\x00.google.com` passed `endsWith()` but `getaddrinfo()` truncated at the null byte) that defeated its allowlist for ~130 releases over ~5.5 months [#3]; AWS Bedrock AgentCore leaked a full bidirectional DNS-tunneling C2 because recursive DNS was left open inside the "isolated" sandbox [#3]; and Oasis "Claudy Day" exfiltrated full Claude.ai history by abusing the *one* allowlisted host (`api.anthropic.com`) as a confused-deputy channel [#3]. The bypass classes are generic and structural — SNI/Host spoofing, IP-direct after self-resolution, allowed-domain abuse, parser-differential injection — none of which a name-matching allowlist can close [#15]. Bulkhead must decide what egress guarantee it ships, and at which layer.

## Decision drivers

- Every shipping vendor allowlist that has been audited was bypassed; a name-matching policy is not a boundary [#3][#15].
- Every demonstrated break is one of two failure modes: a *placement* failure (the check sits where a compromised guest can route around it — in-guest resolver, raw socket, IP-direct) or a *parser-differential* failure (policy and connect layers disagree on one input) [#15].
- The enforcement point must sit at or below the host boundary, because everything inside the guest — agent, in-guest proxy, in-guest resolver — is assumed compromised under our threat model [#15].
- DNS itself is an exfiltration channel; HTTP-only allowlists that leave resolution open provide no protection (CVE-2025-55284) [#14].
- A hard *content* guarantee for allowed destinations requires TLS termination, which has real compatibility cost [#15].

## Considered options

- **Domain/SNI allowlist as the boundary (incumbent default).** Rejected. Domain-only filtering confines *which hostname* but not *what flows to it*; bypassable by SNI spoof, host-header spoof, IP-direct, and allowed-domain abuse, and repeatedly broken in the wild [#3][#15].
- **Model-layer destination blocking.** Rejected outright. Reputation/training filters are trivially evaded by domain selection (Claude refused oast.me but accepted wuzzi.net) and are not a network boundary [#14].
- **microVM boundary alone.** Rejected as an egress control. Firecracker performs no traffic filtering; its only native egress lever is a rate limiter — a quantity control, never a destination/content policy [#15]. The VM gives isolation, not confinement.
- **Structural confinement (no route out of the agent netns) + host-side mediating proxy, allowlist advisory.** Accepted. This is the only placement the guest cannot route around, and the only design that closes both the placement and parser-differential failure classes [#14][#15].

## Decision

Bulkhead WILL enforce egress structurally, not by policy:

1. The agent runs in a network namespace with **no default route**. The only path out is a host-mediated proxy reachable over a unix-domain socket; there is no in-guest route, resolver, or raw-socket path to the network.
2. **Drop `CAP_NET_RAW`** in the sandbox so the agent cannot forge packets or bypass the mediated resolver with raw sockets [#14].
3. The proxy **blocks in-guest DNS resolution** and resolves on the host, closing the DNS-tunnel exfiltration leg [#14].
4. For any allowed destination, the proxy **TLS-terminates and content-inspects**, using a single canonicalized parse of the destination shared by the policy check and the connect call (eliminating endsWith/getaddrinfo-class differentials) [#15].
5. **Domain allowlists are advisory hints, never the boundary.** The boundary is the no-route netns plus the mediating proxy [#15].

*Tier mapping (per the ADR-0031 taxonomy):* items 1–2 (no-route netns, `CAP_NET_RAW` drop) are host/namespace-level levers for the trusted/low-threat and hostile (microVM) tiers. For the **default Sentry tier** the network path is the Sentry's reimplemented userspace netstack, so the equivalent control is binding that netstack solely to the host-mediated proxy socket — the Sentry is given no host route and no raw-socket egress. Items 3–5 (host-side DNS, TLS-terminating proxy, advisory allowlist) then apply identically across tiers.

## Consequences

### Positive

- Closes the IP-direct, raw-socket, SNI/Host-spoof, and DNS-tunnel bypass classes at a placement the compromised guest cannot route around [#14][#15].
- A shared canonical parse eliminates the parser-differential class that defeated Claude Code for ~130 versions [#3][#15].
- Content inspection of allowed destinations closes the body-exfiltration hole that domain-only filtering cannot — the gap Oasis "Claudy Day" exploited [#3][#15].
- Makes egress a genuine OS-level guarantee — single-trace, completely mediatable — rather than best-effort policy [#15].

### Negative / costs

- The workload must trust the proxy's re-signing CA, injected into the guest trust store; the signing key becomes a high-value target [#15].
- **Pinned-certificate and mutual-TLS endpoints break outright** through the proxy. We accept this as the cost of a hard guarantee, handling unavoidable cases via narrow, audited passthrough exceptions — each understood as an uninspected channel [#15].
- TLS termination adds operational and latency overhead on every allowed flow.

### Residual risks the OS cannot touch

- **A legitimately-allowed destination abused as a covert channel.** Once a flow to an allowed host is authorized, the proxy must permit it; content rules narrow but cannot eliminate steganographic exfiltration within allowed bodies [#14][#15].
- **DNS-metadata leakage** absent full content inspection of the resolution path [#14][#15].
- **The hijacked-but-authorized action.** The model deciding to send data to an allowed endpoint is a model-layer defect (lethal trifecta / indirect injection) that no egress layer can fix [#14].

## Confidence & open questions

High confidence on the structural decision: the no-route + host-proxy + CAP_NET_RAW-drop pattern is directly endorsed by both [#14] and [#15], and no surveyed system achieves *provable* confinement, so this is a high-assurance best-effort posture, not a proof [#15]. Open: the size and audit process for the pinned-cert/mTLS passthrough exception list; whether content rules add measurable margin against a determined covert-channel adversary, or merely raise cost.

## Evidence (source reports)

- [#3] Agent-sandbox egress bypasses — the exfil-path failure mode (Claude Code SOCKS5 null-byte; AgentCore DNS C2; Oasis "Claudy Day"). 28/29 claims verified.
- [#15] Egress control as the agent-sandbox market's structural weak point (bypass-class matrix; TLS-termination costs; provable-confinement gap). 22/22 verified.
- [#14] Agent threat matrix — what the OS can enforce (DNS-blocking egress proxy + CAP_NET_RAW drop; CVE-2025-55284; allowed-but-abused channel residual). 26/26 verified.

## Related ADRs

- **ADR-0035 (action authorization):** egress mediation constrains the exfiltration *leg*, but the hijacked-but-authorized action and intent-derivation are authorization-layer problems the egress proxy cannot decide.
- **ADR-0031 / isolation substrate:** the microVM/reimplemented-kernel boundary gives isolation, not egress policy; this ADR places the egress boundary at/below the host, treating the guest as compromised.
- **ADR-0036 (model routing):** a Q-LLM quarantine relies on this egress boundary to ensure the untrusted-content path cannot reach an external communication primitive.

---
*Evidence tags `[#N]` reference the bulkhead deep-research corpus (47 adversarially-verified reports) and `BULKHEAD-DESIGN-BRIEF.md`, kept in the design workspace alongside this repo.*
