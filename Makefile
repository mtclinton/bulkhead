# SPDX-License-Identifier: AGPL-3.0-only
# bulkhead — top-level wrapper around the pinned Buildroot tree.

BULKHEAD_ROOT := $(CURDIR)
BUILDROOT_DIR := $(BULKHEAD_ROOT)/buildroot
EXTERNAL      := $(BULKHEAD_ROOT)/external
OUTPUT        := $(BULKHEAD_ROOT)/output
DEFCONFIG     := bulkhead_defconfig
BR            := $(MAKE) -C $(BUILDROOT_DIR) O=$(OUTPUT) BR2_EXTERNAL=$(EXTERNAL)

.PHONY: help buildroot defconfig image run verify verify-agent-orch verify-e0 verify-hbd verify-attest menuconfig linux-menuconfig \
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
