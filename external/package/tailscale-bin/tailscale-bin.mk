################################################################################
# SPDX-License-Identifier: AGPL-3.0-only
# tailscale-bin — official static Tailscale binaries (pinned, current)
################################################################################

TAILSCALE_BIN_VERSION = 1.98.4
TAILSCALE_BIN_SITE = https://pkgs.tailscale.com/stable
TAILSCALE_BIN_SOURCE = tailscale_$(TAILSCALE_BIN_VERSION)_amd64.tgz
TAILSCALE_BIN_LICENSE = BSD-3-Clause

# Prebuilt static binaries: no build step. The tarball strips to tailscaled,
# tailscale, and a systemd/ dir.
define TAILSCALE_BIN_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/tailscaled $(TARGET_DIR)/usr/sbin/tailscaled
	$(INSTALL) -D -m 0755 $(@D)/tailscale  $(TARGET_DIR)/usr/bin/tailscale
	$(INSTALL) -D -m 0644 $(@D)/systemd/tailscaled.service \
		$(TARGET_DIR)/usr/lib/systemd/system/tailscaled.service
	$(INSTALL) -D -m 0644 $(@D)/systemd/tailscaled.defaults \
		$(TARGET_DIR)/etc/default/tailscaled
endef

$(eval $(generic-package))
