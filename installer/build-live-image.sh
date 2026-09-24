#!/usr/bin/env bash
# Builds the FR_OS hybrid live/installer ISO (phase 5, ROADMAP.md).
#
# Stages this repo's source into the live-build tree's includes.chroot
# (so the in-chroot hook can `pip install` it -- see
# config/hooks/0100-install-frfw.hook.chroot), then runs `lb config`
# + `lb build`, then installer/make-hybrid-uefi-iso.sh to add real UEFI
# boot support on top of `lb build`'s own BIOS-only image (phase 13,
# see ARCHITECTURE.md -- this ancient live-build snapshot can't do
# hybrid BIOS+UEFI itself, see that script's own header for why). Must
# run as root: live-build chroots, mounts, and device nodes all need
# it. Needs `live-build`, `debootstrap`, `xorriso`, `squashfs-tools`,
# `librsvg2-bin`, `syslinux-utils` and friends installed
# (`apt-get install live-build debootstrap xorriso squashfs-tools isolinux
# syslinux-efi syslinux-utils librsvg2-bin grub-pc-bin grub-efi-amd64-bin
# grub-common mtools dosfstools`), and network access to Debian's
# mirrors -- expect this to take a while (debootstrap downloads a base
# system, then every package in frfw.list.chroot, then assembles and
# compresses a squashfs).
#
# `syslinux-utils` (for `isohybrid`, used by --binary-images iso-hybrid)
# and `librsvg2-bin` are easy to miss: nothing in the chroot package list
# needs them, since they're build-*host* tools invoked directly by
# lb_binary_syslinux/lb_binary_iso outside the chroot -- a host missing
# either fails late, well into `lb build`, with an unrelated-looking
# error ("isohybrid: not found" / "rsvg: No such file or directory").
# `grub-efi-amd64-bin`, `grub-common`, `mtools` and `dosfstools` are the
# same kind of build-host-only tool, needed by
# installer/make-hybrid-uefi-iso.sh (grub-mkstandalone, mkfs.vfat,
# mmd/mcopy) rather than by anything inside the chroot -- see that
# script's own header for exactly what each one is for.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LB_DIR="$REPO_ROOT/installer/live-build"
STAGE_DIR="$LB_DIR/config/includes.chroot/opt/frfw-src"

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (live-build needs to chroot/mount)" >&2
    exit 1
fi

# live-build's chroot hooks run via a plain `chroot`, which inherits
# this shell's environment as-is. Some build hosts (anything behind a
# TLS-inspecting proxy -- CI runners, corporate networks, this project's
# own sandboxed dev environment) export CA-bundle override variables
# (PIP_CERT, SSL_CERT_FILE, ...) pointing at a path on the *host*
# filesystem. Inherited unchanged into the chroot, that path doesn't
# exist there, and pip fails with a confusing
# "Could not find a suitable TLS CA certificate bundle" instead of just
# using the chroot's own ca-certificates trust store like a normal,
# unproxied build would. Unsetting them here is a no-op on a plain
# build host and fixes it on a proxied one.
unset PIP_CERT REQUESTS_CA_BUNDLE CURL_CA_BUNDLE SSL_CERT_FILE \
    NODE_EXTRA_CA_CERTS GIT_SSL_CAINFO NIX_SSL_CERT_FILE \
    CARGO_HTTP_CAINFO DENO_CERT HTTPLIB2_CA_CERTS AWS_CA_BUNDLE \
    CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE GRPC_DEFAULT_SSL_ROOTS_FILE_PATH \
    HEX_CACERTS_PATH

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

echo "==> Adding UEFI boot support (installer/make-hybrid-uefi-iso.sh)"
"$REPO_ROOT/installer/make-hybrid-uefi-iso.sh"

echo
echo "==> Build finished. Output:"
ls -la "$LB_DIR"/*.iso 2>/dev/null || echo "  no .iso found -- check the build log above for errors"
