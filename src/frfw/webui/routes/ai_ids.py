"""AI IDS/IPS screen (phase 11: real, kernel-assisted anomaly detection
-- see frfw.ai_ids and ARCHITECTURE.md's phase 11 section; this replaced
an earlier explicit-mock engine, see ROADMAP.md).

Detection and enforcement both happen entirely out-of-band, in the
separate `fr-ai-ids` systemd daemon (frfw.ai_ids.daemon) -- this screen
is purely observational plus a settings form:

- Engine health (`frfw.ai_ids.is_daemon_active`) is a plain
  `systemctl is-active` call, no privilege needed, the same reasoning as
  the ad-block resolver's own status check.
- Currently-quarantined hosts is a live kernel-state query through the
  privileged apply-helper's `ids_quarantine_status` command (the
  unprivileged webUI process cannot read nftables state itself, same as
  every other kernel-state read in this project).
- Recent flagged/quarantined events is a small, unprivileged,
  display-only log the daemon itself writes
  (`frfw.ai_ids.load_recent_events`) -- context only, never the
  authority on who is currently quarantined.

Only the `ai_ids` *settings* (the config.yaml section) go through the
helper's `save_config`, same as every other config change; there is no
"force retrain"/"lock profile" pair here anymore (that was the mock
engine's, and had no meaning for a continuously-running detector) --
this phase's own open issue is that there is also no manual "release
early" action yet for a quarantined IP (see ARCHITECTURE.md), matching
the same gap phase 10 left open for the brute-force jail.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request

from frfw.ai_ids import is_daemon_active, load_recent_events
from frfw.config import ConfigError, parse_config
from frfw.webui.actions import try_save
from frfw.webui.deps import get_ai_ids_state_path, get_helper, get_raw_config, require_login
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


@router.get("/ai-ids")
def show_ai_ids(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
    state_path=Depends(get_ai_ids_state_path),
):
    ai_ids_raw = raw.get("ai_ids") or {}
    config_error = None
    try:
        parse_config(raw)
    except ConfigError as exc:
        config_error = str(exc)

    quarantine_status = helper.ids_quarantine_status()
    quarantined = quarantine_status.get("quarantined", []) if quarantine_status.get("ok") else []
    quarantine_error = None if quarantine_status.get("ok") else quarantine_status.get("message")

    return templates.TemplateResponse(
        request,
        "ai_ids.html",
        {
            "username": username,
            "enabled": bool(ai_ids_raw.get("enabled", False)),
            "excluded_macs": ", ".join(ai_ids_raw.get("excluded_macs") or []),
            "quarantine_duration_seconds": ai_ids_raw.get("quarantine_duration_seconds", 2 * 3600),
            "daemon_active": is_daemon_active(),
            "quarantined": quarantined,
            "quarantine_error": quarantine_error,
            "recent_events": list(reversed(load_recent_events(state_path))),
            "config_error": config_error,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/ai-ids/settings")
def save_settings(
    enabled: bool = Form(False),
    excluded_macs: str = Form(""),
    quarantine_duration_seconds: int = Form(2 * 3600),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    raw["ai_ids"] = {
        "enabled": enabled,
        "excluded_macs": [m.strip() for m in excluded_macs.split(",") if m.strip()],
        "quarantine_duration_seconds": quarantine_duration_seconds,
    }

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with(
            "/ai-ids",
            success="AI IDS settings saved -- restart fr-ai-ids.service (or reboot) to pick up changes",
        )
    return redirect_with("/ai-ids", error=message)
