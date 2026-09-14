#!/usr/bin/env bash
# Phase 2 system integration installer for FR_OS.
#
# Sets up /etc/fr_os, a default config (if none exists yet), the
# fr_os-webui group that will gate access to the apply-helper socket in
# phase 3, and installs/enables the systemd units. Run as root on a
# Debian box that already has `frfw` installed (see README.md) and the
# nftables package present.
#
# This is deliberately a plain shell script rather than a Python module:
# it only runs once per machine (or once per frfw upgrade) and every step
# is a standard sysadmin primitive (install(1), groupadd(8),
# systemctl(1)) -- wrapping that in frfw itself would just be indirection.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR=/etc/fr_os
CONFIG_PATH="$CONFIG_DIR/config.yaml"
SYSTEMD_DIR=/etc/systemd/system
WEBUI_GROUP=fr_os-webui

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root" >&2
    exit 1
fi

echo "==> Creating $CONFIG_DIR"
install -d -m 0755 "$CONFIG_DIR"
install -d -m 0750 "$CONFIG_DIR/backups"

if [[ ! -f "$CONFIG_PATH" ]]; then
    echo "==> No config found at $CONFIG_PATH, installing the example config as a starting point"
    install -m 0640 "$REPO_ROOT/examples/config.yaml" "$CONFIG_PATH"
    echo "    Review/edit it (or re-run 'firewall-cli assign-interfaces') before relying on it."
else
    echo "==> $CONFIG_PATH already exists, leaving it alone"
fi

echo "==> Ensuring group '$WEBUI_GROUP' exists (the phase-3 webUI will run as a member)"
getent group "$WEBUI_GROUP" >/dev/null || groupadd --system "$WEBUI_GROUP"

echo "==> Installing systemd units"
install -m 0644 "$REPO_ROOT/systemd/fr-firewall.service" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-apply-helper.socket" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-apply-helper.service" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-webui.service" "$SYSTEMD_DIR/"

echo "==> Reloading systemd"
systemctl daemon-reload

cat <<'EOF'

Done. Next steps:
  systemctl enable --now fr-firewall
  systemctl enable --now fr-apply-helper.socket

fr-webui.service is a phase-3 placeholder: it is installed but left
disabled, since the real webUI doesn't exist yet.
EOF
