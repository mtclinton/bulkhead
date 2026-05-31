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

echo
echo "Fetched poky + meta-openembedded + meta-rauc @ $BRANCH"
echo "Next: see yocto/README.md to set up the build (bitbake-layers, distro, image)."
