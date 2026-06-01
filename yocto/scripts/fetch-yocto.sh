#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Fetch the pinned Yocto layers for the bulkhead production build. Layers are
# NOT vendored into this repo (see .gitignore); they are cloned at a pinned
# branch so builds are reproducible. meta-bulkhead/ (this repo) is the only
# committed layer.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"   # the yocto/ dir
BRANCH="${YOCTO_BRANCH:-scarthgap}"        # Yocto 5.0 LTS

clone() { # url dir
	local url="$1" dir="$2"
	if [ -d "$ROOT/$dir/.git" ]; then
		echo "$dir present; fetching $BRANCH"
		git -C "$ROOT/$dir" fetch --depth 1 origin "$BRANCH"
		git -C "$ROOT/$dir" checkout -q "$BRANCH" && git -C "$ROOT/$dir" reset -q --hard "origin/$BRANCH"
	else
		git clone --depth 1 --branch "$BRANCH" "$url" "$ROOT/$dir"
	fi
}

clone https://git.yoctoproject.org/poky                    poky
clone https://github.com/openembedded/meta-openembedded    meta-openembedded
clone https://github.com/rauc/meta-rauc                    meta-rauc
# meta-rauc-community/meta-rauc-qemux86: the qemux86-64 GRUB A/B reference (wks,
# grub.cfg/grubenv, boot-image, system.conf) that bulkhead's wic A/B build reuses.
clone https://github.com/rauc/meta-rauc-community          meta-rauc-community
# meta-security (contains meta-tpm): tpm2-tss/tpm2-tools + systemd[tpm2] runtime deps
# for measured boot + the TPM-sealed audit key (ADR-0008).
clone https://git.yoctoproject.org/meta-security            meta-security

echo
echo "Fetched poky + meta-openembedded + meta-rauc + meta-rauc-community + meta-security @ $BRANCH"
echo "Next: see yocto/README.md to set up the build (bitbake-layers, distro, image)."
