#!/usr/bin/env bash
# Builds the FR_OS hybrid live/installer ISO (phase 5, ROADMAP.md).
#
# Stages this repo's source into the live-build tree's includes.chroot
# (so the in-chroot hook can `pip install` it -- see
# config/hooks/live/0100-install-frfw.hook.chroot), then runs `lb config`
# + `lb build`. Must run as root: live-build chroots, mounts, and device
# nodes all need it. Needs `live-build`, `debootstrap`, `xorriso`,
# `squashfs-tools`, `librsvg2-bin`, `syslinux-utils` and friends installed
# (`apt-get install live-build debootstrap xorriso squashfs-tools isolinux
# syslinux-efi syslinux-utils librsvg2-bin grub-pc-bin grub-efi-amd64-bin
# mtools dosfstools`), and network access to Debian's mirrors -- expect
# this to take a while (debootstrap downloads a base system, then every
# package in frfw.list.chroot, then assembles and compresses a squashfs).
#
# `syslinux-utils` (for `isohybrid`, used by --binary-images iso-hybrid)
# and `librsvg2-bin` are easy to miss: nothing in the chroot package list
# needs them, since they're build-*host* tools invoked directly by
# lb_binary_syslinux/lb_binary_iso outside the chroot -- a host missing
# either fails late, well into `lb build`, with an unrelated-looking
# error ("isohybrid: not found" / "rsvg: No such file or directory").
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LB_DIR="$REPO_ROOT/installer/live-build"
STAGE_DIR="$LB_DIR/config/includes.chroot/opt/frfw-src"

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (live-build needs to chroot/mount)" >&2
    exit 1
fi

echo "==> Staging repo source into $STAGE_DIR"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"
rsync -a \
    --exclude ".git" \
    --exclude "installer" \
    --exclude "__pycache__" \
    --exclude "*.egg-info" \
    --exclude ".pytest_cache" \
    "$REPO_ROOT/" "$STAGE_DIR/"

cd "$LB_DIR"

echo "==> lb clean"
lb clean

echo "==> lb config"
lb config

echo "==> lb build (this is the slow part)"
lb build

echo
echo "==> Build finished. Output:"
ls -la "$LB_DIR"/*.iso 2>/dev/null || echo "  no .iso found -- check the build log above for errors"
