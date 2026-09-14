"""AI IDS/IPS screen.

Everything this screen shows comes from `frfw.ai_ids.AIIDSEngine`, which
is an explicit MOCK pending phase 4's real traffic capture -- see that
module's docstring and templates/ai_ids.html's on-page banner. Nothing
here should ever be read as a real security signal.

"Force retrain" and "lock profile" are unprivileged, in-process calls to
the engine -- unlike every other screen's writes, they do NOT go through
`frfw.helper`, because they need no root capability (no nftables/Kea/`ip`
involved) and routing them through the privileged helper would only
widen its attack surface for no reason. Only the `ai_ids` *settings* (the
config.yaml section itself) go through the helper's `save_config`, same
as every other config change.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request

from frfw.ai_ids import AIIDSEngine
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
    state_path=Depends(get_ai_ids_state_path),
):
    ai_ids_raw = raw.get("ai_ids") or {}
    devices = []
    global_progress = 0.0
    config_error = None

    try:
        config = parse_config(raw)
    except ConfigError as exc:
        config_error = str(exc)
    else:
        if config.ai_ids.enabled:
            engine = AIIDSEngine(config, state_path)
            devices = engine.list_devices()
            global_progress = engine.global_learning_progress()

    return templates.TemplateResponse(
        request,
        "ai_ids.html",
        {
            "username": username,
            "enabled": bool(ai_ids_raw.get("enabled", False)),
            "learning_days": ai_ids_raw.get("learning_days", 7),
            "retrain_time": ai_ids_raw.get("retrain_time", "03:30"),
            "excluded_macs": ", ".join(ai_ids_raw.get("excluded_macs") or []),
            "devices": devices,
            "global_progress": round(global_progress),
            "config_error": config_error,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/ai-ids/settings")
def save_settings(
    enabled: bool = Form(False),
    learning_days: int = Form(7),
    retrain_time: str = Form("03:30"),
    excluded_macs: str = Form(""),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    raw["ai_ids"] = {
        "enabled": enabled,
        "learning_days": learning_days,
        "retrain_time": retrain_time,
        "excluded_macs": [m.strip() for m in excluded_macs.split(",") if m.strip()],
    }

    ok, message = try_save(raw, helper)
    if ok:
        return redirect_with("/ai-ids", success="AI IDS settings saved")
    return redirect_with("/ai-ids", error=message)


@router.post("/ai-ids/retrain-all")
def retrain_all(
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    state_path=Depends(get_ai_ids_state_path),
):
    try:
        config = parse_config(raw)
    except ConfigError as exc:
        return redirect_with("/ai-ids", error=str(exc))

    AIIDSEngine(config, state_path).force_retrain(None)
    return redirect_with("/ai-ids", success="Retrain clock reset for all devices")


@router.post("/ai-ids/{mac}/retrain")
def retrain_one(
    mac: str,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    state_path=Depends(get_ai_ids_state_path),
):
    try:
        config = parse_config(raw)
        AIIDSEngine(config, state_path).force_retrain(mac)
    except ConfigError as exc:
        return redirect_with("/ai-ids", error=str(exc))
    except KeyError as exc:
        return redirect_with("/ai-ids", error=str(exc))

    return redirect_with("/ai-ids", success=f"Retrain clock reset for {mac}")


@router.post("/ai-ids/{mac}/lock")
def lock_one(
    mac: str,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    state_path=Depends(get_ai_ids_state_path),
):
    try:
        config = parse_config(raw)
        AIIDSEngine(config, state_path).lock_profile(mac)
    except ConfigError as exc:
        return redirect_with("/ai-ids", error=str(exc))
    except KeyError as exc:
        return redirect_with("/ai-ids", error=str(exc))

    return redirect_with("/ai-ids", success=f"Profile locked for {mac}")
