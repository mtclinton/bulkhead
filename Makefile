# SPDX-License-Identifier: AGPL-3.0-only
# bulkhead — top-level wrapper around the pinned Buildroot tree.

BULKHEAD_ROOT := $(CURDIR)
BUILDROOT_DIR := $(BULKHEAD_ROOT)/buildroot
EXTERNAL      := $(BULKHEAD_ROOT)/external
OUTPUT        := $(BULKHEAD_ROOT)/output
DEFCONFIG     := bulkhead_defconfig
BR            := $(MAKE) -C $(BUILDROOT_DIR) O=$(OUTPUT) BR2_EXTERNAL=$(EXTERNAL)

.PHONY: help buildroot defconfig image run verify verify-agent-orch menuconfig linux-menuconfig \
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
	@echo "  make tsauth-disk    build the Tailscale auth-key provisioning volume"
	@echo "  make verify-tailnet boot with the key volume and assert the node joins"
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

verify-m5:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-m5-check.py

verify-agent-orch:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-agent-orch-check.py

tsauth-disk:
	$(BULKHEAD_ROOT)/scripts/make-tsauth-disk.sh

verify-tailnet:
	python3 $(BULKHEAD_ROOT)/scripts/qemu-tailnet-check.py

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
