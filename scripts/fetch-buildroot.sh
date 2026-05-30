#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Fetch and checkout the pinned Buildroot tree for bulkhead.
#
# Buildroot is NOT vendored into this repo (see .gitignore). It is fetched at a
# pinned, verifiable tag so appliance builds are reproducible. Before relying on
# a build, re-verify the kernel/toolchain version strings (system/Config.in,
# configs/qemu_x86_64_defconfig) against this tag — see
# docs/decisions/0001-foundational-architecture.md.
set -euo pipefail

BUILDROOT_REPO="${BUILDROOT_REPO:-https://gitlab.com/buildroot.org/buildroot.git}"
# Pinned to the latest patch of the 2025.02 LTS line (mature, long-supported).
BUILDROOT_REF="${BUILDROOT_REF:-2025.02.14}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/buildroot"

if [ -d "$DEST/.git" ]; then
  echo "Buildroot already present at $DEST; fetching $BUILDROOT_REF ..."
  git -C "$DEST" fetch --depth 1 origin "refs/tags/$BUILDROOT_REF:refs/tags/$BUILDROOT_REF"
else
  echo "Cloning Buildroot $BUILDROOT_REF ..."
  git clone --depth 1 --branch "$BUILDROOT_REF" "$BUILDROOT_REPO" "$DEST"
fi

git -C "$DEST" -c advice.detachedHead=false checkout --detach "$BUILDROOT_REF"
echo "Buildroot pinned at: $(git -C "$DEST" describe --tags --always)"
