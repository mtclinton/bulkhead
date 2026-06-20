# SPDX-License-Identifier: AGPL-3.0-only
# bulkhead — top-level wrapper around the pinned Buildroot tree.

BULKHEAD_ROOT := $(CURDIR)
BUILDROOT_DIR := $(BULKHEAD_ROOT)/buildroot
EXTERNAL      := $(BULKHEAD_ROOT)/external
OUTPUT        := $(BULKHEAD_ROOT)/output
DEFCONFIG     := bulkhead_defconfig
BR            := $(MAKE) -C $(BUILDROOT_DIR) O=$(OUTPUT) BR2_EXTERNAL=$(EXTERNAL)

.PHONY: help buildroot defconfig image run verify verify-agent-orch verify-e0 verify-hbd verify-attest verify-security-review verify-audit-rotation verify-firecracker-spike verify-firecracker-legs verify-firecracker-agent verify-firecracker-proxy verify-firecracker-jail verify-firecracker-image verify-chain-monitor verify-chain-monitor-live verify-floor-lint verify-hostile-agent verify-runsc-kvm-escape verify-runsc-kvm-nonroot verify-fc-escape verify-fc-jailer verify-fc-jailer-iso menuconfig linux-menuconfig \
        savedefconfig clean distclean

help:
	@echo "bulkhead build targets:"
	@echo "  make buildroot      fetch + checkout the pinned Buildroot tree"
	@echo "  make defconfig      load the bulkhead defconfig into Buildroot"
	@echo "  make image          build the appliance image -> output/images/"
	@echo "  make run            boot the image in qemu (CPU-only)"
	@echo "  make verify         boot the image in qemu and assert the security floor"
	@echo "  make data-disk      build the model data volume (downloads the GGUF)"
	@echo "  make verify-service boot with the data disk and assert local inference"
	@echo "  make verify-router  boot with the data disk and assert request routing"
	@echo "  make verify-egress  boot and assert the default-deny network floor"
	@echo "  make verify-m5      boot and assert provenance + the fail-closed self-test"
	@echo "  make verify-agent-orch  boot and assert sub-agent orchestration (narrow-never-widen + injection-safe)"
	@echo "  make verify-e0      boot, arm E0, and assert the full stack enforces with delegation working"
	@echo "  make verify-hbd     boot the HARDENED image, reboot, assert E0+E2 armed from cold boot with delegation"
	@echo "  make verify-attest  boot under swtpm, assert TPM-quoted proof of the enforcing TCB (+ tamper/replay rejected)"
	@echo "  make tsauth-disk    build the Tailscale auth-key provisioning volume"
	@echo "  make verify-tailnet boot with the key volume and assert the node joins"
	@echo "  make verify-yocto-router  (Yocto wic + swtpm) assert the router /data signed chain survives a reboot"
	@echo "  make verify-egress-reboot (Yocto wic + swtpm) assert the egress /data chain survives a reboot (fail-closed seed)"
	@echo "  make verify-confined-agent (Yocto wic) assert a REAL agent runs in the confined jail (model via router UDS, web via egress proxy)"
	@echo "  make verify-egress-mitm (Yocto wic) assert ADR-0034 inc2 TLS-termination + content inspection (inspect + passthrough arms)"
	@echo "  make verify-quarantine (Yocto wic) assert ADR-0036 Dual-LLM quarantine: injected content cannot trigger a privileged tool"
	@echo "  make verify-security-review (Yocto wic) re-run the 2026-06 review regression suite (R1 gate, R2 broker cap, R3 ro legs, R4 inspect fail-closed)"
	@echo "  make menuconfig     Buildroot menuconfig"
	@echo "  make linux-menuconfig  kernel menuconfig"
	@echo "  make savedefconfig  write the minimal defconfig to external/configs"
	@echo "  make clean          remove build output (keeps downloads)"

buildroot:
	$(BULKHEAD_ROOT)/scripts/fetch-buildroot.sh

defconfig: | $(BUILDROOT_DIR)
	$(BR) $(DEFCONFIG)

image: | $(BUILDROOT_DIR)
	$(BR)

run:
	$(BULKHEAD_ROOT)/scripts/run-qemu.sh

verify:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-floor-check.py

data-disk:
	$(BULKHEAD_ROOT)/scripts/make-data-disk.sh

verify-service:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-service-check.py

verify-router:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-router-check.py

verify-egress:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-egress-check.py

verify-egress-class:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-egress-class-check.py

verify-egress-proxy:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-egress-proxy-check.py

verify-m5:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-m5-check.py

verify-agent-orch:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-agent-orch-check.py

verify-e0:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-e0-check.py

verify-hbd:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-hbd-check.py

verify-attest:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-attest-check.py

tsauth-disk:
	$(BULKHEAD_ROOT)/scripts/make-tsauth-disk.sh

verify-tailnet:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-tailnet-check.py

# Yocto (not Buildroot): boots the wic image under swtpm via yocto/scripts/run-qemu-tpm.sh
# and asserts the router's signed routing-decision chain persists on /data and is appended
# across an in-guest reboot (ADR-0027/0028). Needs a built wic (bitbake bulkhead-image).
verify-yocto-router:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-yocto-router-check.py

# Yocto (not Buildroot): the egress sibling of verify-yocto-router. Boots the wic under swtpm via
# run-qemu-tpm.sh and asserts the EGRESS PROXY's signed egress-decision chain (ADR-0034/0017)
# survives an in-guest reboot AND the proxy comes back fail-closed under its OWN sealed seed
# (BULKHEAD_REQUIRE_SEALED_KEY=1) — a path the router test does not exercise. Needs a built wic.
verify-egress-reboot:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-egress-reboot-check.py

# Yocto: ADR-0040 / security-review R9 — bounded-retention audit-chain segment rotation. Boots the wic,
# drops in a tiny rotation threshold so the egress chain rotates several times and HEAD-prunes (oldest
# segment > 1, exercising the verifier's retained-head anchor), asserts verify-audit OK + footprint
# bounded, then reboots and proves the boot gate stays green over the segmented+pruned chain (no
# false-brick) and appends continue link-continuous across the seam. Needs a built wic.
verify-audit-rotation:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-audit-rotation-check.py

# Host-side (NOT the qemu harness — it has no nested KVM): ADR-0031 Firecracker HOSTILE-tier spike. Boots
# a microVM with bulkhead's Yocto guest kernel under KVM and asserts host-surface collapse (a separate
# guest kernel, 8/8). Needs a built wic (for the deploy bzImage) + firecracker ($FIRECRACKER) + /dev/kvm.
verify-firecracker-spike:
	sh $(BULKHEAD_ROOT)/scripts/fc-spike-check.sh

# Host-side (NOT the qemu harness): ADR-0042 Firecracker mediated-channel SLICE 1. Boots a no-network
# microVM and proves the in-VM agent reaches a host endpoint ONLY through a provisioned vsock leg + the
# bulkhead-fc-vsockmux (CONNECT->OK), an unprovisioned port is refused, and there is no NIC. 8/8. Needs a
# built wic + firecracker ($FIRECRACKER) + /dev/kvm; exits 2 INCONCLUSIVE where /dev/kvm is absent.
verify-firecracker-legs:
	sh $(BULKHEAD_ROOT)/scripts/fc-legs-check.sh

# Host-side: ADR-0042 Firecracker mediated-channel SLICE 2. Boots a no-network microVM running the
# UNCHANGED bulkhead-agent probe, its UNIX legs backed by the in-guest fc-vsockmux forwarder, and asserts
# NOROUTE + ISOLATED (no direct net) + PROXY-OK (the agent reaches the host via leg->forwarder->vsock->mux)
# — proving the agent binary is byte-identical across tiers. Needs a built wic + firecracker + /dev/kvm.
verify-firecracker-agent:
	sh $(BULKHEAD_ROOT)/scripts/fc-agent-check.sh

# Host-side: ADR-0042 Firecracker mediated-channel SLICE 3. Boots the UNCHANGED agent in a no-network
# microVM with its egress leg pointed (over vsock) at the REAL bulkhead-egress-proxy on the host; asserts
# the real allowlist (PROXY-OK allow + PROXY-DENY deny) holds over vsock AND the proxy signed the decisions
# into its chain which `bulkhead-collector verify-audit` then verifies. Needs a built wic + firecracker +
# /dev/kvm + python3.
verify-firecracker-proxy:
	sh $(BULKHEAD_ROOT)/scripts/fc-proxy-check.sh

# Host-side: ADR-0042 Firecracker mediated-channel SLICE 4 confinement assertions. Boots a microVM + mux
# and asserts (lsof/ss) that the running firecracker holds NO host internet socket (no network egress
# primitive), the per-instance dir holds EXACTLY the 3 expected sockets, and the mux is their sole
# listener. The jailer's uid/chroot/netns/cgroup confinement is root-gated (run as root with $JAILER to
# wrap firecracker under it; the deployable hardened unit + jailer launcher land in slice 6).
verify-firecracker-jail:
	sh $(BULKHEAD_ROOT)/scripts/fc-jail-check.sh

# ADR-0042 IN-IMAGE landing gate (slices 5-6). NOT a boot check (needs no /dev/kvm): asserts the deployable
# tier actually shipped into the built bulkhead-image rootfs and is well-formed — the three binaries +
# the ELF guest vmlinux + mkfs.ext4 present; the launcher parses + keeps its no-NIC/no-ldd invariants; both
# @.service templates present + well-formed; the mux unit keeps its hardening floor; the agent unit gates on
# the mux + proxy + selftest. Inspects the rootfs dir (or the deployed tar.bz2); exits 2 without a built image.
verify-firecracker-image:
	sh $(BULKHEAD_ROOT)/scripts/fc-image-check.sh

# Off-box audit-chain monitor (bulkhead-chain-monitor) — host-side proof of the pin/advance/rewind-detect/
# missed-attestation state machine via injected fakes (no qemu, no /dev/kvm). The live end-to-end arm
# (boot the wic, poll it, truncate a chain -> alert) is verify-chain-monitor-live. See deploy/chain-monitor.md.
verify-chain-monitor:
	cd $(BULKHEAD_ROOT)/src/chain-monitor && go vet ./... && go test -count=1 ./...

# Build-time security-floor lint (no qemu/hardware): static guard over the shipped units + kernel fragments
# for load-bearing invariants the ADRs require but had no automated check — seccomp jails deny io_uring by
# name, the kernel compiles it out (EXPERT-gated, both fragments), the mux floor is a superset of its
# siblings, and the mediation units carry the hardening floor. Runs its own negative self-test.
verify-floor-lint:
	sh $(BULKHEAD_ROOT)/scripts/floor-lint.sh --selftest

# LIVE arm: boot the wic under swtpm, run the monitor BINARY off-box against the booted appliance over a
# guest-exec bridge (fresh-nonce quote -> verify -> pin the control HEAD = GREEN), then truncate the chain's
# tail on the box and re-poll (the prior-pinned HEAD is no longer an ancestor -> the monitor ALERTS). Needs a
# built wic + swtpm + a host Go toolchain.
verify-chain-monitor-live:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-chain-monitor-check.py

# HOSTILE-agent containment proof (PRODUCTION-READINESS [6]): boots the wic and runs the agent's
# `probe-escape` vehicle inside the REAL confined jail — the agent actively attempts io_uring / setuid /
# capset / new-userns / ptrace / module-load / raw-io / direct-egress / FS-write / control-socket escapes —
# and asserts EVERY vector is contained and E0+E2 survive the assault. Needs a built wic.
verify-hostile-agent:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-hostile-agent-check.py

# Hostile-agent containment for the SUBSTRATE tiers on REAL /dev/kvm (probe-escape in substrate mode):
# gVisor/runsc under --platform=kvm, and a Firecracker microVM. Assert every HOST-CROSSING vector (io_uring,
# direct egress, the control socket, a host-only secret outside the sandbox) is contained; in-sandbox-privilege
# ops are SANDBOX-PRIV (contained by the Sentry/VM, ADR-0031 residual). Need real /dev/kvm + runsc/firecracker.
verify-runsc-kvm-escape:
	sh $(BULKHEAD_ROOT)/scripts/runsc-kvm-escape-check.sh
verify-fc-escape:
	sh $(BULKHEAD_ROOT)/scripts/fc-escape-check.sh

# runsc DEFAULT-tier NON-ROOT in-sandbox hardening on REAL /dev/kvm (PRODUCTION-READINESS [81]). Proves the
# production launcher's non-root OCI user is BOTH safe (in-sandbox setuid/capset now CONTAINED, not SANDBOX-PRIV)
# AND functional (the non-root agent still reaches its mode-0666 mediated leg and READS its 0444 task credential
# through the o+x creds dir). --platform=kvm, production-minimal bundle. Needs real /dev/kvm + runsc.
verify-runsc-kvm-nonroot:
	sh $(BULKHEAD_ROOT)/scripts/runsc-kvm-nonroot-check.sh

# ADR-0042 JAILER confinement of the VMM, LIVE on real /dev/kvm: runs the firecracker jailer (per-instance
# non-root uid + chroot + cgroup) wrapping firecracker inside a privileged container (root context + real
# /dev/kvm), and asserts the running VMM is non-root, chrooted (host fs invisible), and holds no inet socket.
# Needs real /dev/kvm + the docker group (root context).
verify-fc-jailer:
	sh $(BULKHEAD_ROOT)/scripts/fc-jailer-check.sh

# ADR-0042 two-instance cross-isolation under the jailer, LIVE on real /dev/kvm: boots TWO jailed microVMs
# and asserts they run as distinct non-root uids in mode-0700 per-uid chroots — so two hostile tenants cannot
# reach each other's jail. Needs real /dev/kvm + the docker group.
verify-fc-jailer-iso:
	sh $(BULKHEAD_ROOT)/scripts/fc-jailer-iso-check.sh

# Yocto: a REAL bulkhead agent runtime inside the ADR-0034 confined jail (the inc1 follow-up that
# replaces the probe-egress vehicle with the actual tool-using loop). Boots the wic, points the
# router's local backend + the proxy allowlist at a loopback mockchat, runs the confined agent on
# a FETCH-ONLY task, and asserts it reached FINAL with its model leg over the router UDS and its
# web fetch through the egress proxy (signed into the /data chain). Needs a built wic.
verify-confined-agent:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-confined-agent-check.py

# Yocto: ADR-0034 increment 2 (TLS-termination + content inspection). Boots the wic, asserts the
# on-device re-signing CA was provisioned, then runs a confined agent twice: an inspect-marked host
# is TLS-terminated + content-inspected (Hook=inspect, method=GET) and a passthrough-marked host is
# spliced opaque (Hook=passthrough). A loopback TLS mockchat stands in for the real upstream. Needs a built wic.
verify-egress-mitm:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-egress-mitm-check.py

# Yocto: ADR-0036 model-routing quarantine (Dual-LLM, slice A). Boots the wic, runs the confined
# agent in BULKHEAD_AGENT_QUARANTINE mode on a FETCH->EXTRACT->REPORT plan whose fetched page body
# carries a prompt injection ("TOOL request_egress public" / "TOOL fetch http://evil.invalid/"), and
# asserts control-flow integrity: the injection reaches the REPORT only as DATA, NO privileged tool
# fires (no escalation, no evil.invalid fetch), and the egress chain grows by exactly the one
# planned loopback fetch and still verifies signed. Needs a built wic.
verify-quarantine:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-quarantine-injection-check.py

# Yocto: ADR-0031 substrate integration, slice 1. Boots the wic and proves gVisor/runsc runs in the
# appliance with host-surface collapse — a workload under runsc reports gVisor's reimplemented kernel
# (~4.4.x / "Starting gVisor"), not the host 6.x. Probes platform/flag combos. Needs a built wic.
verify-runsc:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-runsc-substrate-check.py

# Yocto: ADR-0031 substrate integration, slice 3. Boots the wic and proves an agent UNDER gVisor/runsc
# keeps its single MEDIATED way out: with --host-uds=open it reaches the host egress proxy UDS across
# the Sentry boundary (PROXY-OK), the allowlist is enforced (PROXY-DENY), no direct egress
# (NOROUTE/ISOLATED), io_uring is ENOSYS, and the proxy signs the egress into its /data chain. Needs a built wic.
verify-runsc-egress:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-runsc-egress-check.py

# Yocto: ADR-0031 substrate integration, slice 4. Boots the wic and runs a FULL real agent loop under
# runsc with BOTH mediated channels — the model leg (router UDS) and the web leg (egress proxy UDS) —
# reached across the Sentry via host-uds. Asserts the loop reached FINAL (inference worked), the fetch
# went through the proxy (HTTP 200), and the egress was signed. Needs a built wic.
verify-runsc-agent:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-runsc-agent-check.py

# Yocto: ADR-0031 substrate integration, slice 5. The PRODUCTION runtime form: `runsc run` over an OCI
# bundle with a MINIMAL rootfs (only the agent binary + the two UDS legs bind-mounted, the host fs is
# NOT exposed). Runs a real agent loop, both legs mediated, egress signed. Needs a built wic.
verify-runsc-run:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-runsc-run-check.py

# Yocto: ADR-0031 slice 6. The DEPLOYABLE form: `systemctl start bulkhead-agent-runsc@<inst>` launches
# a substrate-jailed agent (unit -> launcher -> minimal-rootfs OCI bundle -> runsc run), task delivered
# injection-safely as a credential. Asserts a real agent loop, both legs mediated, egress signed, the
# bundle reaped on stop. Needs a built wic (re-pin bulkhead-units).
verify-runsc-unit:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-runsc-unit-check.py

# Yocto: capstone — the two flagship defenses compose. An ADR-0036 CaMeL-quarantine agent run UNDER
# the ADR-0031 gVisor substrate: a prompt injection in fetched content is inert (control-flow
# integrity) AND the agent runs under host-surface collapse (kernel 4.4.0), egress still signed.
verify-runsc-quarantine:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-runsc-quarantine-check.py

# Yocto: security-review R1 — the egress proxy's fail-closed boot gate. Boots the wic, forges a record
# into the /data egress chain, and asserts the gate (proxy Requires=selftest->verify-audit) REFUSES the
# proxy (and transitively a confined agent) under a tampered chain, while a clean chain still permits it.
verify-egress-gate:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-egress-gate-check.py

# Yocto: the re-runnable regression suite for the 2026-06 shipped-architecture security review
# (docs/security-reviews/2026-06-shipped-isolation-review.md): R1 fail-closed egress gate, R2 broker
# delegated-EXPAND cap, R3 runsc ro UDS legs (defense-in-depth, userns-DAC-attributed), R4 inspect
# fail-closed. Runs the four live arms SEQUENTIALLY — each boots its own qemu, never in parallel
# (two concurrent VMs contend and trip the boot timeouts). Stops on the first failure. Needs a built wic.
verify-security-review:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-egress-gate-check.py
	python3 $(BULKHEAD_ROOT)/scripts/qemu-agent-orch-check.py
	python3 $(BULKHEAD_ROOT)/scripts/qemu-runsc-run-check.py
	python3 $(BULKHEAD_ROOT)/scripts/qemu-egress-mitm-check.py
	python3 $(BULKHEAD_ROOT)/scripts/qemu-audit-rotation-check.py

# Yocto: the RAUC A/B atomic update + rollback (ADR-0003). Boots slot A, `rauc install`s the
# bundle (attached as a raw virtio disk) into slot B, reboots into B, then mark-bads B and
# reboots to prove the rollback to A. Needs a built wic AND bundle (bitbake bulkhead-image
# bulkhead-bundle).
verify-rauc:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-rauc-check.py

# Host-side (no qemu): exercise the RAUC no-downgrade install-check hook's exit codes (ADR-0039). A
# downgrade must reject (exit >=10); same/newer/missing must allow (exit 0). Fast, CI-runnable.
verify-rauc-hook:
	@sh $(BULKHEAD_ROOT)/scripts/rauc-hook-check.sh

menuconfig: | $(BUILDROOT_DIR)
	$(BR) menuconfig

linux-menuconfig: | $(BUILDROOT_DIR)
	$(BR) linux-menuconfig

savedefconfig: | $(BUILDROOT_DIR)
	$(BR) savedefconfig BR2_DEFCONFIG=$(EXTERNAL)/configs/$(DEFCONFIG)

clean: | $(BUILDROOT_DIR)
	$(BR) clean

distclean:
	rm -rf $(OUTPUT)

$(BUILDROOT_DIR):
	@echo "Buildroot tree missing at $(BUILDROOT_DIR) — run 'make buildroot' first." >&2
	@exit 1
