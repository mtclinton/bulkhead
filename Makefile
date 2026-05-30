# SPDX-License-Identifier: AGPL-3.0-only
# bulkhead — top-level wrapper around the pinned Buildroot tree.

BULKHEAD_ROOT := $(CURDIR)
BUILDROOT_DIR := $(BULKHEAD_ROOT)/buildroot
EXTERNAL      := $(BULKHEAD_ROOT)/external
OUTPUT        := $(BULKHEAD_ROOT)/output
DEFCONFIG     := bulkhead_defconfig
BR            := $(MAKE) -C $(BUILDROOT_DIR) O=$(OUTPUT) BR2_EXTERNAL=$(EXTERNAL)

.PHONY: help buildroot defconfig image run verify menuconfig linux-menuconfig \
        savedefconfig clean distclean

help:
	@echo "bulkhead build targets:"
	@echo "  make buildroot      fetch + checkout the pinned Buildroot tree"
	@echo "  make defconfig      load the bulkhead defconfig into Buildroot"
	@echo "  make image          build the appliance image -> output/images/"
	@echo "  make run            boot the image in qemu (CPU-only)"
	@echo "  make verify         assert the security floor is live (run in guest)"
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
	$(BULKHEAD_ROOT)/scripts/verify-floor.sh

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
