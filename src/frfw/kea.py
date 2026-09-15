"""Generates and applies a Kea DHCPv4 config from the frfw `dhcp` section.

Kea (not dnsmasq/isc-dhcp-server) is the chosen DHCP backend -- see
ROADMAP.md phase 3. Kea's config is plain JSON, which happens to make
generation much simpler than the nftables text format: build a dict and
`json.dumps` it, instead of hand-assembling syntax.

Kea's own Debian package installs `kea-dhcp4-server` (running as the
unprivileged `_kea` user) reading /etc/kea/kea-dhcp4.conf; frfw treats
that file as fully generated (never hand-edited) and restarts the service
after writing it, mirroring how frfw.apply treats the nftables ruleset.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from frfw.config.schema import Config, DhcpPool

KEA_CONFIG_PATH = Path("/etc/kea/kea-dhcp4.conf")
KEA_SERVICE_NAME = "kea-dhcp4-server"


class KeaError(Exception):
    """Raised when Kea rejects a generated config or it fails to apply."""


@dataclass(frozen=True)
class KeaApplyResult:
    applied: bool
    message: str


def build_kea_config(config: Config) -> dict:
    """Translate `config.dhcp` into a Kea `Dhcp4` config dict."""
    interfaces_by_zone = {iface.zone: iface for iface in config.interfaces.values()}

    listen_interfaces = []
    subnets = []
    for zone, pool in config.dhcp.zones.items():
        iface = interfaces_by_zone[zone]
        listen_interfaces.append(iface.device)
        subnets.append(_build_subnet(iface.address, pool))

    return {
        "Dhcp4": {
            "interfaces-config": {"interfaces": listen_interfaces},
            "lease-database": {"type": "memfile", "lfc-interval": 3600},
            "valid-lifetime": 3600,
            "subnet4": subnets,
        }
    }


def _build_subnet(iface_address: str, pool: DhcpPool) -> dict:
    interface = ipaddress.IPv4Interface(iface_address)

    reservations = [
        {
            "hw-address": r.mac_address,
            "ip-address": r.address,
            **({"hostname": r.hostname} if r.hostname else {}),
        }
        for r in pool.reservations
    ]

    return {
        "subnet": str(interface.network),
        "pools": [{"pool": f"{pool.range_start} - {pool.range_end}"}],
        "valid-lifetime": pool.lease_time,
        "option-data": [
            {"name": "routers", "data": str(interface.ip)},
            {"name": "domain-name-servers", "data": ", ".join(pool.dns_servers)},
        ],
        "reservations": reservations,
    }


def render_kea_config(config: Config) -> str:
    return json.dumps(build_kea_config(config), indent=2) + "\n"


def check_syntax(config_text: str) -> None:
    """Validate `config_text` with `kea-dhcp4 -t`, touching no running daemon.

    Kea's config tester needs a real file path (no stdin support), so this
    writes to a throwaway temp file first.
    """
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(config_text)
        temp_path = f.name
    try:
        _run_kea_test(temp_path)
    finally:
        Path(temp_path).unlink(missing_ok=True)


def apply_dhcp_config(
    config: Config, *, dry_run: bool = False, config_path: Path = KEA_CONFIG_PATH
) -> KeaApplyResult:
    """Validate and, unless `dry_run`, write and load the Kea DHCPv4 config.

    A no-op (returns `applied=False`) if `config.dhcp` has no zones.
    """
    if not config.dhcp.zones:
        return KeaApplyResult(applied=False, message="No DHCP zones configured")

    config_text = render_kea_config(config)
    check_syntax(config_text)

    if dry_run:
        return KeaApplyResult(applied=False, message="Kea config syntax OK (dry-run, not applied)")

    _require_root()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(config_text)
    _restart_kea_service()

    return KeaApplyResult(applied=True, message=f"Kea DHCP config applied ({config_path})")


def _require_root() -> None:
    if os.geteuid() != 0:
        raise KeaError("Applying the DHCP config requires root privileges.")


def _run_kea_test(path: str) -> None:
    try:
        proc = subprocess.run(["kea-dhcp4", "-t", path], capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise KeaError("'kea-dhcp4' binary not found; install kea-dhcp4-server") from exc
    if proc.returncode != 0:
        raise KeaError(
            proc.stderr.strip() or proc.stdout.strip()
            or f"kea-dhcp4 -t exited with status {proc.returncode}"
        )


def _restart_kea_service() -> None:
    try:
        proc = subprocess.run(
            ["systemctl", "restart", KEA_SERVICE_NAME], capture_output=True, text=True
        )
    except FileNotFoundError as exc:
        raise KeaError("'systemctl' not found") from exc
    if proc.returncode != 0:
        raise KeaError(proc.stderr.strip() or f"failed to restart {KEA_SERVICE_NAME}")
