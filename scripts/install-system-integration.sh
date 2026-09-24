#!/usr/bin/env bash
# System integration installer for FR_OS.
#
# Sets up /etc/fr_os, a default config (if none exists yet), the
# fr_os-webui system user/group that the webUI runs as and that gates
# access to the apply-helper socket, and installs the systemd units. Run
# as root on a Debian box that already has `frfw` (with the `webui`
# extra) installed (see README.md) and the nftables/kea-dhcp4-server
# packages present.
#
# This is deliberately a plain shell script rather than a Python module:
# it only runs once per machine (or once per frfw upgrade) and every step
# is a standard sysadmin primitive (install(1), useradd(8),
# systemctl(1)) -- wrapping that in frfw itself would just be indirection.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR=/etc/fr_os
CONFIG_PATH="$CONFIG_DIR/config.yaml"
WEBUI_STATE_DIR="$CONFIG_DIR/webui"
SYSTEMD_DIR=/etc/systemd/system
WEBUI_USER=fr_os-webui

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root" >&2
    exit 1
fi

echo "==> Ensuring user/group '$WEBUI_USER' exists (the webUI runs as this unprivileged user)"
id -u "$WEBUI_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$WEBUI_USER"

echo "==> Creating $CONFIG_DIR"
install -d -m 0755 -o root -g root "$CONFIG_DIR"
install -d -m 0750 -o root -g root "$CONFIG_DIR/backups"
install -d -m 0750 -o "$WEBUI_USER" -g "$WEBUI_USER" "$WEBUI_STATE_DIR"

echo "==> Creating /opt/fr_os/releases (update mechanism's extracted release cache)"
install -d -m 0755 -o root -g root /opt/fr_os
install -d -m 0755 -o root -g root /opt/fr_os/releases

echo "==> Writing initial OpenSSL PQC config fragment (classical-only until enabled on the webUI's System screen)"
# fr-webui.service unconditionally sets OPENSSL_CONF to this path, so it
# must exist before fr-webui ever starts, not just after the first
# `apply` -- see frfw.pqc's module docstring.
python3 -c "
from pathlib import Path
from frfw.pqc import write_openssl_pqc_conf
write_openssl_pqc_conf(Path('$CONFIG_DIR/webui_pqc_openssl.cnf'), hybrid=False)
"

if [[ ! -f "$CONFIG_PATH" ]]; then
    echo "==> No config found at $CONFIG_PATH, installing the example config as a starting point"
    install -m 0640 -o root -g "$WEBUI_USER" "$REPO_ROOT/examples/config.yaml" "$CONFIG_PATH"
    echo "    Review/edit it (or re-run 'firewall-cli assign-interfaces') before relying on it."
else
    echo "==> $CONFIG_PATH already exists; ensuring it is readable by '$WEBUI_USER'"
    chgrp "$WEBUI_USER" "$CONFIG_PATH"
    chmod 0640 "$CONFIG_PATH"
fi

echo "==> Installing systemd units"
install -m 0644 "$REPO_ROOT/systemd/fr-firewall.service" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-apply-helper.socket" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-apply-helper.service" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-webui.service" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-ai-ids.service" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-iot-scan.service" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-iot-scan.timer" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-update-helper.socket" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-update-helper.service" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-adblock-refresh.service" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-adblock-refresh.timer" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-adblock-dns.service" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-xdp-sni-logger.service" "$SYSTEMD_DIR/"
install -m 0644 "$REPO_ROOT/systemd/fr-appid.service" "$SYSTEMD_DIR/"

echo "==> Reloading systemd"
systemctl daemon-reload

cat <<EOF

Done. Next steps:
  firewall-cli set-admin-password        # set the webUI's admin password
  systemctl enable --now fr-firewall
  systemctl enable --now fr-apply-helper.socket
  systemctl enable --now fr-webui        # https://<router-ip>/
  systemctl enable --now fr-ai-ids                 # real-time AI IDS/IPS anomaly detection
  systemctl enable --now fr-iot-scan.timer         # IoT device discovery/isolation (needs iot.enabled)
  systemctl enable --now fr-xdp-sni-logger        # XDP SNI filter event log (needs xdp_sni_filter.enabled)
  systemctl enable --now fr-appid                  # app identification (idles until app_control.enabled)
  systemctl enable --now fr-update-helper.socket   # webUI's Update screen
  systemctl enable --now fr-adblock-refresh.timer  # daily ad-block list refresh (needs 'dnsmasq' installed)

The webUI's self-signed TLS cert is generated on its first start
(stored under $WEBUI_STATE_DIR); your browser will warn about it until
you replace it with a real certificate.

Note: the AI IDS/IPS screen is a mock pending phase 4's real traffic
capture -- see ROADMAP.md and the frfw.ai_ids module docstring.

Note: the ad-block screen (phase 9) needs the 'dnsmasq' package
installed (frfw runs its own dedicated instance, fr-adblock-dns.service
-- it never touches the system's default dnsmasq.service/dnsmasq.conf,
if either is also installed for something unrelated). Nothing is
fetched until either 'firewall-cli adblock-refresh' is run once (or
the webUI's "Refresh now" button is clicked) -- the daily timer above
only keeps an already-populated list current.
EOF
