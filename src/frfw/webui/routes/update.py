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
from frfw.webui.actions import try_save
from frfw.webui.deps import (
    get_helper,
    get_raw_config,
    get_update_helper,
    get_update_state_path,
    require_login,
)
from frfw.webui.helper_client import HelperClient, UpdateHelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


def _resolve_repo(raw: dict) -> str:
    try:
        config = parse_config(raw)
    except ConfigError:
        return update_mod.DEFAULT_REPO
    return config.update.repo or update_mod.DEFAULT_REPO


def _auto_install_security(raw: dict) -> bool:
    return (raw.get("update") or {}).get("auto_install_security") is True


def _kernel_updates(raw: dict) -> bool:
    return (raw.get("update") or {}).get("kernel_updates", True) is not False


def _kernel(helper: UpdateHelperClient) -> tuple[dict | None, str | None]:
    """The kernel card (ROADMAP SEC-14): its status lives on the
    persistence partition, root's, so it comes from the update-helper."""
    try:
        result = helper.kernel("kernel_status")
    except Exception as exc:  # noqa: BLE001 -- the page must render without the helper
        return None, f"the update-helper did not answer: {exc}"
    if not result.get("ok"):
        return None, result.get("message") or "no answer"
    return result.get("kernel"), None


@router.get("/update")
def show_update(
    request: Request,
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    state_path: Path = Depends(get_update_state_path),
    update_helper: UpdateHelperClient = Depends(get_update_helper),
):
    repo = _resolve_repo(raw)
    check_result = None
    check_error = None
    try:
        check_result = update_mod.check_latest(installed_version, repo=repo)
    except update_mod.UpdateError as exc:
        check_error = str(exc)

    state = update_mod.load_state(current_version=installed_version, path=state_path)
    # What fr-update-check.timer last found (security-lessons G10/J3).
    periodic = update_mod.read_check_cache(Path(request.app.state.update_check_path),
                                           current_version=installed_version)
    kernel, kernel_error = _kernel(update_helper)

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
            "periodic": periodic,
            "auto_install_security": _auto_install_security(raw),
            "kernel": kernel,
            "kernel_error": kernel_error,
            "kernel_updates": _kernel_updates(raw),
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


@router.post("/update/auto-security")
def save_auto_security(
    enabled: bool = Form(False),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    """Security-lessons J3: the opt-in to let the router install signed
    security releases by itself (fr-update-check.timer, twice a day)."""
    section = dict(raw.get("update") or {})
    section["auto_install_security"] = enabled
    raw["update"] = section
    ok, message = try_save(raw, helper)
    if not ok:
        return redirect_with("/update", error=message)
    if enabled:
        return redirect_with("/update", success="Security releases will be installed automatically")
    return redirect_with("/update", success="Automatic install of security releases is off")


def _kernel_action(helper: UpdateHelperClient, cmd: str, failed: str):
    try:
        result = helper.kernel(cmd)
    except Exception as exc:  # noqa: BLE001
        return redirect_with("/update", error=f"{failed}: {exc}")
    if result.get("ok"):
        return redirect_with("/update", success=result.get("message") or "Done")
    return redirect_with("/update", error=result.get("message") or failed)


@router.post("/update/kernel/check")
def kernel_check(
    username: str = Depends(require_login),
    helper: UpdateHelperClient = Depends(get_update_helper),
):
    """Look for Debian's newer kernel now instead of at the daily check."""
    return _kernel_action(helper, "kernel_check", "Could not start the check")


@router.post("/update/kernel/try")
def kernel_try(
    username: str = Depends(require_login),
    helper: UpdateHelperClient = Depends(get_update_helper),
):
    """ROADMAP SEC-14: stage the kernel that is ready and reboot into its
    trial -- an admin's decision only (require_login refuses viewers on
    every POST). The router keeps it only if it comes up on it."""
    return _kernel_action(helper, "kernel_try", "Could not start the trial")


@router.post("/update/kernel/cancel")
def kernel_cancel(
    username: str = Depends(require_login),
    helper: UpdateHelperClient = Depends(get_update_helper),
):
    return _kernel_action(helper, "kernel_cancel", "Could not remove the staged kernel")


@router.post("/update/kernel-updates")
def save_kernel_updates(
    enabled: bool = Form(False),
    username: str = Depends(require_login),
    raw: dict = Depends(get_raw_config),
    helper: HelperClient = Depends(get_helper),
):
    """ROADMAP SEC-14: whether fr-kernel-prepare.timer fetches Debian's
    newer kernel (on by default). Trying one stays the admin's."""
    section = dict(raw.get("update") or {})
    section["kernel_updates"] = enabled
    raw["update"] = section
    ok, message = try_save(raw, helper)
    if not ok:
        return redirect_with("/update", error=message)
    if enabled:
        return redirect_with("/update", success="Debian's kernel fixes are fetched daily, ready to try")
    return redirect_with("/update", success="Kernel updates are off")
