"""Ad-block screen (phase 9, see frfw.adblock and frfw.adblock.dns_service).

Settings (enabled/source_urls/xdp_critical_limit) follow the same "edit
the raw YAML dict, validate, save through the privileged helper" pattern
as every other screen (see frfw.webui.actions.try_save) -- saving here
never fetches anything or touches the resolver directly; that happens
either on the next `apply` (which only reconciles the resolver's
running state, see frfw.provision's docstring) or when an admin clicks
"Refresh now" (which goes through the apply-helper's `refresh_adblock`
socket command, since downloading megabytes of third-party blocklist
data and writing under /etc/fr_os is exactly the kind of privileged
operation this webUI process must never do itself).

The live domain count and resolver-active badge are both read directly,
unprivileged, in this process -- counting lines in a world-readable
hosts file and `systemctl is-active` need no elevated access, unlike
frfw.ztna's kernel-state reads (see frfw.adblock.count_blocked_domains /
frfw.adblock.dns_service.is_resolver_active for why each is safe here).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request

from frfw.adblock import DEFAULT_SOURCE_URLS, count_blocked_domains
from frfw.adblock.dns_service import is_resolver_active
from frfw.webui.actions import try_save
from frfw.webui.deps import get_adblock_hosts_path, get_helper, get_raw_config, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


@router.get("/adblock")
def show_adblock(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    adblock_hosts_path: Path = Depends(get_adblock_hosts_path),
):
    adblock_raw = raw.get("adblocker") or {}
    enabled = bool(adblock_raw.get("enabled", False))
    source_urls = list(adblock_raw.get("source_urls") or [])
    xdp_critical_limit = int(adblock_raw.get("xdp_critical_limit", 0) or 0)

    domain_count = count_blocked_domains(adblock_hosts_path)
    resolver_active = is_resolver_active()

    if resolver_active:
        status_label, badge_class = "Active", "badge-green"
    elif enabled:
        status_label, badge_class = "Enabled, not yet applied -- run Apply", "badge-yellow"
    else:
        status_label, badge_class = "Disabled", "badge-red"

    return templates.TemplateResponse(
        request,
        "adblock.html",
        {
            "username": username,
            "enabled": enabled,
            "source_urls": source_urls,
            "source_urls_text": "\n".join(source_urls),
            "default_source_url": DEFAULT_SOURCE_URLS[0],
            "xdp_critical_limit": xdp_critical_limit,
            "domain_count": domain_count,
            "status_label": status_label,
            "badge_class": badge_class,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/adblock/settings")
def save_settings(
    enabled: bool = Form(False),
    source_urls: str = Form(""),
    xdp_critical_limit: int = Form(0),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    urls = []
    for line in source_urls.replace(",", "\n").splitlines():
        url = line.strip()
        if url and url not in urls:
            urls.append(url)

    raw["adblocker"] = {
        "enabled": enabled,
        "source_urls": urls,
        "xdp_critical_limit": xdp_critical_limit,
    }

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with(
            "/adblock",
            success="Ad-block settings saved -- click Apply on the dashboard to "
            "start/stop the resolver",
        )
    return redirect_with("/adblock", error=message)


@router.post("/adblock/refresh")
def refresh_now(
    username: str = Depends(require_login),
    helper: HelperClient = Depends(get_helper),
):
    result = helper.refresh_adblock()
    if result.get("ok"):
        return redirect_with("/adblock", success=result.get("message", "Refreshed"))
    return redirect_with("/adblock", error=result.get("message") or "Refresh failed")
