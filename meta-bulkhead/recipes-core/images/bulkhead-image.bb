# SPDX-License-Identifier: AGPL-3.0-only
SUMMARY = "bulkhead agent appliance image"
LICENSE = "AGPL-3.0-only"

inherit core-image

# Immutable rootfs; mutable state (audit log, tailscaled/credential state, model)
# lives on a separate persistent partition, not a RAUC slot.
IMAGE_FEATURES += "read-only-rootfs"

# ADR-0027 production seam: a fixed system group so the router's per-boot DynamicUser can write its
# persistent signed routing-decision chain on /data across reboots. Each boot the router gets a DIFFERENT
# dynamic uid, so it cannot OWN the persistent dir/files — instead a group-writable, setgid chain dir is
# group-owned by this group and the router joins it via SupplementaryGroups (see bulkhead-router-data.conf).
# Baked into /etc/group at image build because read-only-rootfs leaves no writable /etc for runtime
# sysusers. Only the router (a DynamicUser service) needs it; the User=root collector/broker chains do not.
# The name is deliberately distinct from the router unit's DynamicUser name to avoid a transient-user clash.
inherit extrausers
EXTRA_USERS_PARAMS = "groupadd -r bulkhead-audit;"

IMAGE_INSTALL += " \
    bulkhead-router \
    bulkhead-agent \
    bulkhead-collector \
    bulkhead-units \
    llama-cpp \
    tailscale \
    nftables \
    curl \
    rauc \
    dnsmasq \
    kernel-image \
    tpm2-tools \
"
# kernel-image puts /boot/bzImage in each rootfs slot so GRUB can load it per-slot
# (rauc.slot=A|B). No kernel-modules: the security floor + qemu's virtio/ext4/vfat
# drivers are built-in (the bare-qemu boot mounted root with no initramfs), and the
# lockdown LSM would block loading unsigned modules regardless — so they'd be ~500M
# of dead weight. Any genuinely-needed driver becomes a built-in in the fragment.
# rauc carries the system.conf + ca keyring (meta-rauc/meta-rauc-qemux86).
# tpm2-tools (+ its tpm2-tss dep) from meta-security/meta-tpm: guest-side PCR read and
# the measured-boot event log check (ADR-0008). systemd[tpm2] (distro PACKAGECONFIG)
# pulls the tpm2-tss runtime that unseals LoadCredentialEncrypted via the TPM.

# --- RAUC A/B disk assembly (wic) ---
# wic = the partitioned A/B disk; ext4 = the per-slot rootfs the bundle ships;
# tar.bz2 = what the RAUC rootfs slot packages.
IMAGE_FSTYPES = "tar.bz2 ext4 wic"
WKS_FILE = "bulkhead-grub-efi.wks"
# The EFI/grubenv partitions are raw-copied from boot-image's deploy artifacts.
do_image_wic[depends] += "boot-image:do_deploy"
# 4K-align the rootfs (RAUC adaptive 'block-hash-index' friendliness + clean slots).
IMAGE_ROOTFS_ALIGNMENT = "4"

# Resolve via the systemd-resolved STUB (127.0.0.53), not resolved's upstream
# resolv.conf. The upstream file can't express dnsmasq's :5353 port and is empty under
# UseDNS=false; the stub forwards to dnsmasq, which gates egress via the nft allowlist.
ROOTFS_POSTPROCESS_COMMAND += "bulkhead_resolv_stub;"
bulkhead_resolv_stub() {
    ln -sf ../run/systemd/resolve/stub-resolv.conf ${IMAGE_ROOTFS}${sysconfdir}/resolv.conf
}

# --- Production build hardening ---
# A shippable image MUST NOT carry dev conveniences (empty root password, an
# auto-login serial console, an ssh server, etc.). Production builds set
# BULKHEAD_PRODUCTION = "1" (see yocto/conf/local.conf.production.sample); this then
# fails the build LOUDLY if any insecure image feature leaked in — e.g. poky's default
# EXTRA_IMAGE_FEATURES ?= "debug-tweaks", or the dev A/B-test local.conf. Dev/test
# builds simply leave BULKHEAD_PRODUCTION unset and are unaffected.
python () {
    if d.getVar('BULKHEAD_PRODUCTION') != '1':
        return
    feats = set((d.getVar('IMAGE_FEATURES') or '').split()) | \
            set((d.getVar('EXTRA_IMAGE_FEATURES') or '').split())
    forbidden = {'debug-tweaks', 'empty-root-password', 'allow-empty-password',
                 'allow-root-login', 'post-install-logging', 'serial-autologin-root',
                 'ssh-server-openssh', 'ssh-server-dropbear'}
    leaked = sorted(feats & forbidden)
    if leaked:
        bb.fatal("BULKHEAD_PRODUCTION=1 but insecure/dev image feature(s) present: %s. "
                 "Build with yocto/conf/local.conf.production.sample, not the dev/test "
                 "local.conf." % ", ".join(leaked))
    # RAUC-audit fix: a production build MUST ship a real RAUC device keyring (the off-repo CA), not
    # meta-rauc's dummy stub — otherwise the appliance trusts the wrong anchor / cannot verify any update
    # (fail-closed brick), and the production gate would have rubber-stamped it. The runtime keyring is
    # rauc-conf's ${BULKHEAD_RAUC_KEYDIR}/ca.cert.pem (bbwarn-only upstream); require it here.
    keydir = d.getVar('BULKHEAD_RAUC_KEYDIR')
    capath = os.path.join(keydir, 'ca.cert.pem') if keydir else ''
    if not capath or not os.path.exists(capath) or 'BEGIN CERTIFICATE' not in open(capath).read():
        bb.fatal("BULKHEAD_PRODUCTION=1 but the RAUC device keyring is not a real CA. Set "
                 "BULKHEAD_RAUC_KEYDIR to an off-repo directory containing a valid ca.cert.pem (the "
                 "update trust anchor); without it the build silently ships meta-rauc's dummy stub and "
                 "the appliance can verify NO bundle. (BULKHEAD_RAUC_KEYDIR=%r)" % keydir)
}
