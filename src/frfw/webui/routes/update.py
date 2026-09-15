"""Update mechanism screen (phase 6, see frfw.update and ARCHITECTURE.md).

Version *checking* is unprivileged and computed fresh on every page
load -- a read-only HTTPS GET to GitHub, same pattern as the AI IDS
screen's live-computed progress (see that route's docstring): no root
capability needed, so no reason to route it through a privileged
helper. Only *applying* an update or rolling back goes through
`frfw.helper.update_client`'s separate, dedicated privileged socket
(see `frfw.helper.update_server` for why that is its own daemon rather
than reusing the firewall apply-helper's).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request

from frfw import __version__ as installed_version
from frfw import update as update_mod
from frfw.config import ConfigError, parse_config
from frfw.webui.deps import (
    get_raw_config,
    get_update_helper,
    get_update_state_path,
    require_login,
)
from frfw.webui.helper_client import UpdateHelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


def _resolve_repo(raw: dict) -> str:
    try:
        config = parse_config(raw)
    except ConfigError:
        return update_mod.DEFAULT_REPO
    return config.update.repo or update_mod.DEFAULT_REPO


@router.get("/update")
def show_update(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    state_path: Path = Depends(get_update_state_path),
):
    repo = _resolve_repo(raw)
    check_result = None
    check_error = None
    try:
        check_result = update_mod.check_latest(installed_version, repo=repo)
    except update_mod.UpdateError as exc:
        check_error = str(exc)

    state = update_mod.load_state(current_version=installed_version, path=state_path)

    return templates.TemplateResponse(
        request,
        "update.html",
        {
            "username": username,
            "repo": repo,
            "installed_version": installed_version,
            "check_result": check_result,
            "check_error": check_error,
            "state": state,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/update/apply")
def apply_update(
    version: str = Form(...),
    username: str = Depends(require_login),
    helper: UpdateHelperClient = Depends(get_update_helper),
):
    result = helper.apply(version)
    if result.get("ok"):
        return redirect_with(
            "/update",
            success=result.get("message", "Update applied")
            + " -- the webUI will restart in a few seconds.",
        )
    return redirect_with("/update", error=result.get("message") or "Update failed")


@router.post("/update/rollback")
def rollback_update(
    username: str = Depends(require_login),
    helper: UpdateHelperClient = Depends(get_update_helper),
):
    result = helper.rollback()
    if result.get("ok"):
        return redirect_with(
            "/update",
            success=result.get("message", "Rolled back")
            + " -- the webUI will restart in a few seconds.",
        )
    return redirect_with("/update", error=result.get("message") or "Rollback failed")
