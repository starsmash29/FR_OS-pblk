"""`GET /metrics`: a native Prometheus text-exposition-format endpoint
(phase 12 -- see ARCHITECTURE.md for why this isn't "phase 11": that
number was already used by the AI IDS/IPS work completed earlier).

No `require_login`: a Prometheus scrape config carries a bearer token,
not a session cookie. The token (`metrics.token_sha256`, phase 20, see
frfw.metrics.metrics_access) is what turns the endpoint on: without one
it answers 404, as a feature that is off (ROADMAP SEC-3, review v0.2.0
R11). It used to answer anyone who could reach the webUI's port --
counts of banned and quarantined hosts, the IoT inventory, the hardware
-- and every request made the root helper run its `nft` reads. Neither
an unconfigured nor an unauthenticated request does any work here: the
answer comes before anything is gathered.

An authenticated scrape's text is kept for CACHE_SECONDS, keyed by the
config, so not even a Prometheus scraping faster than that -- or several
of them -- makes the helper work more than once per window. A config
change shows at once (it changes the key); the kernel-side counts are at
most CACHE_SECONDS old, well inside any scrape interval.

Everything gathered here is either read directly from `/proc`, `/sys`,
or `os.statvfs` (no privilege needed, see frfw.metrics's own docstring
for why), or via the same privileged apply-helper socket every other
screen already uses for a kernel-state read -- this route itself never
touches `nft`, `dmidecode`, or any other privileged interface directly.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time

from fastapi import APIRouter, Depends, Header
from fastapi.responses import Response

from frfw.config import ConfigError, parse_config
from frfw.metrics import METRICS_DENIED, METRICS_OFF, generate_metrics_text, metrics_access
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

#: How long an authenticated scrape's text is served again (see above).
CACHE_SECONDS = 15.0

_cache_lock = threading.Lock()
_cache: dict = {}  # {"key": str, "until": float, "text": str}


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def _cache_key(raw: dict, *paths_) -> str:
    blob = json.dumps([raw, [str(p) for p in paths_]], sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


@router.get("/metrics")
def metrics(
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
    adblock_hosts_path=Depends(get_adblock_hosts_path),
    iot_inventory_path=Depends(get_iot_inventory_path),
    adblock_category_dir=Depends(get_adblock_category_dir),
    appid_usage_path=Depends(get_appid_usage_path),
    tlsfp_state_path=Depends(get_tlsfp_state_path),
    authorization: str | None = Header(default=None),
) -> Response:
    access = metrics_access(raw, authorization)
    if access == METRICS_OFF:
        return Response(
            content="metrics are off: generate a token (System screen, or firewall-cli metrics-token --generate)\n",
            status_code=404, media_type="text/plain",
        )
    if access == METRICS_DENIED:
        return Response(
            content="bearer token required\n", status_code=401,
            headers={"WWW-Authenticate": 'Bearer realm="fr_os metrics"'}, media_type="text/plain",
        )
    key = _cache_key(raw, adblock_hosts_path, iot_inventory_path, adblock_category_dir, appid_usage_path,
                     tlsfp_state_path)
    with _cache_lock:
        if _cache.get("key") == key and time.monotonic() < _cache["until"]:
            return Response(content=_cache["text"], media_type="text/plain; version=0.0.4")
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
    with _cache_lock:
        _cache.update(key=key, until=time.monotonic() + CACHE_SECONDS, text=text)
    return Response(content=text, media_type="text/plain; version=0.0.4")
