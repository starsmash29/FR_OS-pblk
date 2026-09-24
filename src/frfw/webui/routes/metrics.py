"""`GET /metrics`: a native Prometheus text-exposition-format endpoint
(phase 12 -- see ARCHITECTURE.md for why this isn't "phase 11": that
number was already used by the AI IDS/IPS work completed earlier).

Deliberately public/unauthenticated (no `require_login`), matching how
Prometheus itself and essentially every metrics exporter in existence
works -- a scrape target is expected to sit behind network-level access
control (a firewall rule, a private management VLAN), not a login form;
forcing session-cookie auth into a Prometheus scrape config is exactly
the kind of friction this endpoint exists to avoid. See
ARCHITECTURE.md's own note on the resulting exposure (counts of banned/
quarantined hosts, hardware inventory, interface byte counters) to
anyone who can reach the webUI's HTTPS port at all -- a real deployment
should restrict scraping at the network layer, e.g. with a
`require_ztna`-gated rule or a dedicated management-only zone.

Everything gathered here is either read directly from `/proc`, `/sys`,
or `os.statvfs` (no privilege needed, see frfw.metrics's own docstring
for why), or via the same privileged apply-helper socket every other
screen already uses for a kernel-state read -- this route itself never
touches `nft`, `dmidecode`, or any other privileged interface directly.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from frfw.config import ConfigError, parse_config
from frfw.metrics import generate_metrics_text
from frfw.webui.deps import (
    get_adblock_category_dir,
    get_adblock_hosts_path,
    get_appid_usage_path,
    get_tlsfp_state_path,
    get_helper,
    get_iot_inventory_path,
    get_raw_config,
)
from frfw.webui.helper_client import HelperClient

router = APIRouter()


@router.get("/metrics")
def metrics(
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
    adblock_hosts_path=Depends(get_adblock_hosts_path),
    iot_inventory_path=Depends(get_iot_inventory_path),
    adblock_category_dir=Depends(get_adblock_category_dir),
    appid_usage_path=Depends(get_appid_usage_path),
    tlsfp_state_path=Depends(get_tlsfp_state_path),
) -> Response:
    try:
        config = parse_config(raw)
    except ConfigError:
        # An on-disk config that currently fails validation must never
        # turn a monitoring endpoint into a 500 -- report whatever needs
        # no config at all (hardware metrics, the helper-backed status
        # counts) and skip the rest, the same graceful-degradation
        # behavior the dashboard route already applies when
        # parse_config fails.
        config = None

    text = generate_metrics_text(
        config,
        helper,
        adblock_hosts_path=adblock_hosts_path,
        iot_inventory_path=iot_inventory_path,
        adblock_category_dir=adblock_category_dir,
        appid_usage_path=appid_usage_path,
        tlsfp_state_path=tlsfp_state_path,
    )
    return Response(content=text, media_type="text/plain; version=0.0.4")
