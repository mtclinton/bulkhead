# ADR-0018: Harden by default — ship the image booting E0-ARMED (+E2)

Status: Accepted
Date: 2026-06-03
Relates to: ADR-0004 (E0–E3 enforce + the TCB model; the observe-floor default), ADR-0005 (agent
jail runner; the +ExecStartPre happens-before so agents fork post-arm), ADR-0006 (inter-agent
egress delegation; the broker socket), ADR-0016 (E0-armable delegation — the collector as sole
bpf() write chokepoint; this ADR converts its "armable + opt-in" into "enforced by default"),
ADR-0017 (sign control writes).

## Context

ADR-0016 made the full E0–E3 stack ARMABLE alongside working delegation: the broker becomes TCB by
collector-granted membership, agent/broker map writes route through the collector control socket,
and `bulkhead-enforce.service` blocks (ExecStartPre=`ctl wait-broker-tcb`) until the broker cgid is
in `tcb_cgroups` so E0 can never arm ahead of broker-TCB. But the shipped image still booted
default-OBSERVE: `bulkhead-enforce.service` and `bulkhead-enforce-egress.service` were NOT in the
units recipe `SYSTEMD_SERVICE`, so the kernel guarantee was opt-in. `make verify-e0` proves the
stack is ARMABLE by IMPERATIVELY starting the broker then `enforce on` — it does not prove the box
BOOTS armed.

Confirmed in source before deciding:

- `bulkhead-broker.socket` is the SOLE creator of `/run/bulkhead` (`RuntimeDirectory=bulkhead`) and
  the SOLE owner of `/run/bulkhead/broker.sock` (`ListenStream=`, `RemoveOnStop=yes`).
  `bulkhead-collector.service:31` comments it depends on that dir existing early to create
  `control.sock` under `ProtectSystem=strict`.
- `bulkhead-broker.service` is socket-activated, has NO `[Install]`, and starts lazily on first
  agent connect — so at cold boot the broker is NOT running, its cgroup
  `/sys/fs/cgroup/system.slice/bulkhead-broker.service` does NOT exist, and `ctl wait-broker-tcb`
  (which resolves the cgid from that fixed path) cannot succeed — the E0 gate would time out and
  enforce would degrade to observe.
- `brokerListener` (broker.go:206-218) prefers `LISTEN_FDS` (fd 3) else does
  `os.Remove(brokerSockPath)` + `net.Listen` — so a broker started WITHOUT `LISTEN_FDS` STEALS the
  `.socket`-owned path (split-brain double-listener vs `RemoveOnStop=yes`). `scripts/qemu-e0-check.py`
  bare-starts the broker (`systemctl start bulkhead-broker.service`, no `LISTEN_FDS`) and today
  relies on exactly this path-bind.

The single genuine de-race for hardened-by-default is therefore: make the broker RUN (cgroup
present, TCB-registered) at boot, through the socket, WITHOUT the path-steal primitive.

## Decision

Ship E0-ARMED (lsm/bpf deny) AND E2-ARMED (socket_connect per-agent egress) at cold boot.

1. KEEP socket activation. `bulkhead-broker.socket` stays the sole `/run/bulkhead` creator
   (`RuntimeDirectory=bulkhead`) and sole `broker.sock` owner — no ownership moves, so the
   collector's `control.sock` dependency is untouched. We reject dropping the socket: it would
   orphan the deterministic dir-owner and couple `/run/bulkhead`'s lifetime to a broker restart.

2. BOOT-TRIGGER the broker as a service. `bulkhead-broker.service` gains `[Install]
   WantedBy=multi-user.target` plus `Wants=`/`After=bulkhead-broker.socket`. multi-user.target
   pulls in the broker; the socket (ordered first, listening) makes PID-1 pass the activation fd, so
   `brokerListener` takes the `FileListener(fd 3)` branch (no path rebind) and `brokerRegisterTCB()`
   runs before it serves. The broker cgroup now EXISTS at boot, so `ctl wait-broker-tcb` resolves —
   and the E0 arm releases. We reject a separate "warmup connect" oneshot: the service `[Install]`
   is a more deterministic trigger and needs no new verb/unit.

3. FAIL-CLOSED `brokerListener` (belt-and-suspenders). When `LISTEN_FDS` is absent the broker now
   RETURNS AN ERROR instead of `os.Remove`+`net.Listen` — it never steals the `.socket`-owned path.
   A dev/Buildroot opt-out `BULKHEAD_BROKER_PATH_BIND=1` restores the legacy bind. This removes the
   split-brain primitive outright, so the boot-start topology is robust even if the fd hand-off ever
   fails.

4. AUTO-ENABLE in `bulkhead-units_0.1.0.bb` `SYSTEMD_SERVICE`: add `bulkhead-broker.service`,
   `bulkhead-enforce.service`, `bulkhead-enforce-egress.service` (keep `bulkhead-broker.socket`).
   Bump `SRCREV` to the commit carrying the unit + `broker.go` changes.

5. E2 is also default-armed: E0 alone leaves per-agent egress in observe (the manifests only bite
   under socket_connect-enforce), so shipping E0 without E2 is a half-guarantee. E2 has no
   broker-TCB dependency, so it arms in parallel.

6. Boot-race fix (adversarial review). Boot-starting the broker introduced a foot-race: the
   collector is `Type=exec` (active at `execve`, not when it binds `control.sock` as its LAST
   startup step), and the broker's first act is to register TCB over that socket. A single dial
   would lose the race (immediate ENOENT) and, with the unit's fatal-no-`Restart=` exit, leave the
   broker dead → the enforce gate times out → E0 silently degrades to observe (fail-SAFE, but
   defeating the deterministic-armed guarantee). Fixed two ways: `brokerRegisterTCB` now POLLS
   (re-dials up to 30s, like `ctl wait-broker-tcb`) for the not-yet-listening socket, and
   `bulkhead-broker.service` gains `Restart=on-failure`/`RestartSec=2` so a lost race self-heals.
   The LIVE cold-boot test then surfaced the SAME race on a second path: `bulkhead-enforce-egress`
   (E2) routes `enforce on socket_connect` through the control socket but — unlike E0, gated by the
   polling `ctl wait-broker-tcb` — has NO gate, so it lost the race, `Fatalf`'d, and silently left
   E2 in OBSERVE (per-agent egress unenforced while E0 was armed). Fixed at the root: the routed
   `enforce` (and `brokerRegisterTCB`) now use a shared `controlRPCRetry` that re-dials the control
   socket until OK or a bounded deadline, so any boot-time routed control write tolerates a
   still-starting collector. The operator/soft-disarm path dials once (the collector is long up).
   The review also confirmed the show-stopper risk is ABSENT: default-armed E2 leaves a non-agent
   cgroup with no `egress_policy` entry at verdict ALLOW (`provenance.bpf.c`), so router/tailscaled/
   llama/DHCP/DNS boot egress is untouched, and no non-TCB `bpf(2)` runs before the arm.

The arm still flows through the UNCHANGED collector + enforce.service path; only WHEN it fires (boot
vs operator) changes — so every ADR-0016 fail-safe is preserved bit-for-bit.

## Verification

A new `scripts/qemu-hbd-check.py` + `make verify-hbd`, keeping `make verify-e0` (armable/opt-in) as
the regression. The HBD harness does ZERO imperative `systemctl start broker/enforce`, REBOOTS once,
and asserts BEFORE any console bpf: (1) `is-active` enforce/enforce-egress/broker all active from
cold boot; (2) the broker journal shows the `LISTEN_FDS`/`FileListener` path, no "refusing to bind",
and `ctl wait-broker-tcb` == OK; (3) a non-TCB console `egress clear self` EPERMs (RC!=0) with no
prior arm; (4) REBOOT then re-assert (1)+(3) — the deterministic cold-boot default, not a first-boot
fluke; (5) delegation narrow-never-widen runs under cold-boot-E0 (child manifest == parent ∩
requested, child public fetch E2-DENIED, child FINALs, broker signs the record); (6) restart the
collector and assert degrade-to-observe-then-reconverge-to-armed with `control.sock` surviving; (7)
`systemctl stop bulkhead-enforce` re-opens console bpf (RC==0) — soft-disarm under cold-boot-E0; (8)
both signed audit chains verify. `qemu-e0-check.py` is updated so its bare broker start no longer
trips the fail-closed guard (socket-fd path, or the `BULKHEAD_BROKER_PATH_BIND=1` dev opt-out).

## Seam

A future unit that issues a non-TCB `bpf()` BEFORE `bulkhead-enforce.service` in the boot graph
would be silently EPERM'd by default-armed E0 (and, if it cascaded a unit failure into
`boot-complete.target`, could trip a RAUC rollback). The `qemu-hbd` proof catches it at integration
time; the durable guard — a static boot-graph lint asserting "no non-TCB `bpf()` before
`bulkhead-enforce.service`" — is deferred. Also deferred: a RAUC posture decision on whether a
hardened slot whose broker crash-loops should "enforce-or-roll-back" vs the current never-brick
default (degrade to observe) — the default stays degrade-to-observe; and an OPERATOR-VISIBLE
"booted UNARMED" signal (an `OnFailure=` target on the enforce units) so a degraded-to-observe boot
is not silent (today the retry+`Restart=` make it rare and it fails safe, but a deployment that
treats observe-when-it-should-enforce as an incident would want the alert).