# SPDX-License-Identifier: AGPL-3.0-only
# Measured boot (ADR-0008): poky's grub-efi GRUB_BUILDIN lacks the `tpm` module, so as
# built GRUB performs NO measurement. Adding it makes GRUB extend PCR 8 (its commands +
# the kernel cmdline incl. rauc.slot=A|B) and PCR 9 (the bzImage it loads) before handing
# off — the bootloader link of the OVMF->GRUB->kernel->systemd measured-boot chain.
GRUB_BUILDIN:append = " tpm"
