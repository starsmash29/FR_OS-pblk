"""WebUI accounts (phase 18): `/users` for admins, `/account` for everyone.

- `/users` (admin role only, see deps.require_admin): list accounts, add
  one with a role, change a role, reset a password, delete -- the store
  refuses anything that would leave no admin -- and the recent audit log.
- `/account`: any logged-in account can change its own password, after
  confirming the current one. Its session cookie is reissued, since the
  password change ends every session opened with the old password.
"""

from __future__ import annotations

import time
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from frfw.admin_account import ROLES, AccountError, validate_password
from frfw.webui import audit
from frfw.webui.auth import COOKIE_NAME, AdminStore, SessionManager
from frfw.webui.deps import (
    get_admin_store,
    get_audit_log_path,
    get_session_manager,
    require_admin,
    require_login,
)
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


def _format_ts(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if isinstance(ts, (int, float)) else "-"


@router.get("/users")
def list_users(
    request: Request,
    username: str = Depends(require_admin),
    admin_store: AdminStore = Depends(get_admin_store),
    audit_log_path: Path = Depends(get_audit_log_path),
):
    entries = audit.read_recent(audit_log_path, limit=200)
    for entry in entries:
        entry["when"] = _format_ts(entry.get("ts"))
    return templates.TemplateResponse(
        request,
        "users.html",
        {
            "username": username,
            "users": sorted(admin_store.users().values(), key=lambda a: a.username),
            "roles": ROLES,
            "audit": entries,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


def _account_action(action, success: str):
    try:
        action()
    except AccountError as exc:
        return redirect_with("/users", error=str(exc))
    return redirect_with("/users", success=success)


@router.post("/users/add")
def add_user(
    new_username: str = Form(...),
    new_password: str = Form(...),
    role: str = Form(...),
    username: str = Depends(require_admin),
    admin_store: AdminStore = Depends(get_admin_store),
):
    return _account_action(
        lambda: admin_store.add_user(new_username.strip(), new_password, role),
        f"User {new_username.strip()!r} added as {role}",
    )


@router.post("/users/{target}/role")
def change_role(
    target: str,
    role: str = Form(...),
    username: str = Depends(require_admin),
    admin_store: AdminStore = Depends(get_admin_store),
):
    return _account_action(lambda: admin_store.set_role(target, role), f"{target!r} is now {role}")


@router.post("/users/{target}/password")
def reset_password(
    target: str,
    new_password: str = Form(...),
    username: str = Depends(require_admin),
    admin_store: AdminStore = Depends(get_admin_store),
):
    def action():
        if admin_store.get(target) is None:
            raise AccountError(f"No such user {target!r}")
        validate_password(new_password)
        admin_store.set_password(target, new_password)

    return _account_action(action, f"Password of {target!r} reset; their open sessions have ended")


@router.post("/users/{target}/delete")
def delete_user(
    target: str,
    username: str = Depends(require_admin),
    admin_store: AdminStore = Depends(get_admin_store),
):
    return _account_action(lambda: admin_store.delete_user(target), f"User {target!r} deleted")


@router.get("/account")
def show_account(request: Request, username: str = Depends(require_login)):
    return templates.TemplateResponse(
        request,
        "account.html",
        {
            "username": username,
            "role": request.state.user.role,
            "error": request.query_params.get("error"),
            "success": request.query_params.get("success"),
        },
    )


@router.post("/account/password")
def change_own_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    new_password_confirm: str = Form(...),
    username: str = Depends(require_login),
    admin_store: AdminStore = Depends(get_admin_store),
    session_manager: SessionManager = Depends(get_session_manager),
):
    if admin_store.verify(username, current_password) is None:
        return redirect_with("/account", error="Current password is wrong")
    if new_password != new_password_confirm:
        return redirect_with("/account", error="New passwords do not match")
    try:
        validate_password(new_password)
    except AccountError as exc:
        return redirect_with("/account", error=str(exc))
    admin_store.set_password(username, new_password)

    # This session survives (with a fresh cookie); every other session of
    # this account used the old password and has now ended.
    response = RedirectResponse("/account?success=Password+changed", status_code=303)
    response.set_cookie(
        COOKIE_NAME,
        session_manager.create_cookie_value(admin_store.get(username)),
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return response
