#!/usr/bin/env bash
# First-boot setup for an FR_OS installed/live image (see phase 5,
# ROADMAP.md and installer/live-build/). Runs once, as root, via
# fr-first-boot.service; idempotent (checks its own marker file) so a
# re-run -- or the service accidentally firing twice -- is a no-op.
#
# What "no manual package installation/terminal work" (the phase 5
# acceptance criterion) means in practice here: frfw and its
# dependencies are already installed into the image at build time (see
# installer/live-build/config/hooks/); this script only creates
# PER-MACHINE state that cannot be baked into the image (which NIC is
# which, the admin password, TLS keys) and starts the services. The
# admin still has to read the generated password off the console and
# log into the webUI -- that's expected, not "terminal work".
set -euo pipefail

CONFIG_DIR=/etc/fr_os
MARKER="$CONFIG_DIR/.first-boot-done"

if [[ $EUID -ne 0 ]]; then
    echo "fr-first-boot: must run as root" >&2
    exit 1
fi

if [[ -f "$MARKER" ]]; then
    echo "fr-first-boot: already completed ($MARKER exists), skipping"
    exit 0
fi

echo "fr-first-boot: running initial setup..."

install-system-integration.sh

# A DHCP client (ifupdown) on exactly the given ports, started now.
write_dhcp_clients() {
    local file=/etc/network/interfaces.d/fr_os-wan dev
    mkdir -p /etc/network/interfaces.d
    echo "# Written by fr-first-boot: the WAN port's DHCP client." > "$file"
    for dev in "$@"; do
        printf 'allow-hotplug %s\niface %s inet dhcp\n' "$dev" "$dev" >> "$file"
    done
    # In ifup@'s own unit (as on every later boot), not in this one.
    for dev in "$@"; do
        systemctl start --no-block "ifup@$dev.service" || true
    done
}

# Naive zero-touch default: first detected NIC is WAN, second is LAN.
# Matches the common homelab case (exactly two NICs) without requiring
# an interactive wizard; anything more exotic (OPT zones, more than two
# NICs) still needs a manual 'firewall-cli assign-interfaces' or a trip
# through the webUI's Interfaces screen afterwards.
mapfile -t DEVICES < <(firewall-cli detect-interfaces | awk 'NR>1 {print $1}')

WEBUI_HINT=""
if [[ ${#DEVICES[@]} -ge 2 ]]; then
    WAN="${DEVICES[0]}"
    LAN="${DEVICES[1]}"
    firewall-cli assign-interfaces --wan "$WAN" --lan "$LAN" --force
    # The webUI reads the config as the unprivileged fr_os-webui user.
    chgrp fr_os-webui "$CONFIG_DIR/config.yaml"
    chmod 0640 "$CONFIG_DIR/config.yaml"
    echo "fr-first-boot: assigned WAN=$WAN LAN=$LAN (LAN 192.168.1.1/24 with DHCP)"
    # The WAN port gets its address from the upstream network: a DHCP
    # client on it, and on it alone. On the LAN the router *is* the DHCP
    # server, and a client there would flush frfw's static address
    # (the image boots with ip=frommedia so live-boot doesn't put one
    # back on every boot; see installer/live-build/auto/config).
    write_dhcp_clients "$WAN"
    WEBUI_HINT="webUI: https://192.168.1.1/ from a computer on the LAN port ($LAN)"
else
    echo "fr-first-boot: fewer than 2 network interfaces detected (${#DEVICES[@]});" >&2
    echo "  skipping auto-assignment -- run 'firewall-cli assign-interfaces' manually" >&2
    # No LAN to protect: keep whatever there is reachable over DHCP.
    write_dhcp_clients "${DEVICES[@]}"
fi

# The password goes on the console's login screen through a root-only
# /etc/issue.d file (agetty reads it as root), never into the
# world-readable /etc/issue or this unit's journal, and it disappears
# once it has been changed (frfw.initial_password).
firewall-cli set-admin-password --generate --show-on-console

# Where to find the webUI is not a secret: that stays in /etc/issue.
if [[ -n "$WEBUI_HINT" ]]; then
    {
        echo "FR_OS $WEBUI_HINT"
        echo
        cat /etc/issue 2>/dev/null || true
    } > /etc/issue.new
    mv /etc/issue.new /etc/issue
fi

# Each unit on its own: one that fails to start is reported and stays
# enabled (systemd retries it every boot), but doesn't stop the others --
# nor leave first boot unfinished, which would rerun it (and replace the
# admin password) at every boot.
FAILED_UNITS=()
for unit in \
    fr-firewall \
    fr-apply-helper.socket \
    fr-webui \
    fr-ai-ids \
    fr-iot-scan.timer \
    fr-xdp-sni-logger \
    fr-appid \
    fr-schedule-check.timer \
    fr-update-check.timer \
    fr-tls-fp \
    fr-update-helper.socket
do
    systemctl enable "$unit"
    # restart, not start: fr-firewall is already active with the
    # fail-closed baseline (no config existed when it ran at boot).
    if ! systemctl restart "$unit"; then
        FAILED_UNITS+=("$unit")
        echo "fr-first-boot: $unit failed to start -- see 'journalctl -u $unit'" >&2
    fi
done

mkdir -p "$CONFIG_DIR"
touch "$MARKER"
if [[ ${#FAILED_UNITS[@]} -gt 0 ]]; then
    echo "fr-first-boot: done, but these did not start: ${FAILED_UNITS[*]}"
else
    echo "fr-first-boot: done"
fi
