from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from frfw.admin_account import AccountError
from frfw.webui import audit
from frfw.webui.auth import COOKIE_NAME, AdminStore, SessionManager
from frfw.webui.auth_rate_limiter import BruteforceGuard, reject_failed_login
from frfw.webui.client_ip import client_ip
from frfw.webui.deps import (
    get_admin_store,
    get_audit_log_path,
    get_bruteforce_guard,
    get_helper,
    get_session_manager,
    require_login,
)
from frfw.webui.helper_client import HelperClient
from frfw.webui.responses import redirect_with
from frfw.webui.templating import templates

router = APIRouter()


@router.get("/login")
def login_form(request: Request, admin_store: AdminStore = Depends(get_admin_store)):
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            # No account yet: the page says to create one on the router's
            # console. It is never created over the network -- whoever
            # reached the page first would have become admin.
            "no_account": not admin_store.exists(),
            "error": request.query_params.get("error"),
        },
    )


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    admin_store: AdminStore = Depends(get_admin_store),
    session_manager: SessionManager = Depends(get_session_manager),
    helper: HelperClient = Depends(get_helper),
    guard: BruteforceGuard = Depends(get_bruteforce_guard),
    audit_log_path: Path = Depends(get_audit_log_path),
):
    ip = client_ip(request)
    account = admin_store.verify(username, password)
    if account is None:
        audit.append(audit_log_path, {"user": username, "client": ip, "event": "login failed"})
        return reject_failed_login(ip, guard, helper, redirect_path="/login")

    guard.record_success(ip)
    audit.append(audit_log_path, {"user": username, "role": account.role, "client": ip, "event": "login"})
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        COOKIE_NAME,
        session_manager.create_cookie_value(account),
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return response


@router.post("/logout")
def logout(request: Request, session_manager: SessionManager = Depends(get_session_manager)):
    # Security-lessons G7: the session ends on the server, not only in
    # this browser -- a copied cookie stops working too.
    session_manager.revoke_cookie(request.cookies.get(COOKIE_NAME))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE_NAME)
    return response


@router.get("/setup")
def setup_form(request: Request, username: str = Depends(require_login)):
    if not request.state.user.must_change:
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request, "setup.html", {"current": username, "error": request.query_params.get("error")}
    )


@router.post("/setup")
def setup_submit(
    request: Request,
    new_username: str = Form(..., alias="username"),
    password: str = Form(...),
    password_confirm: str = Form(...),
    username: str = Depends(require_login),
    admin_store: AdminStore = Depends(get_admin_store),
    session_manager: SessionManager = Depends(get_session_manager),
    audit_log_path: Path = Depends(get_audit_log_path),
):
    """Security-lessons G1: the generated first-boot account becomes the
    admin's own -- a username that isn't a default, a password nobody
    else has seen."""
    if not request.state.user.must_change:
        return RedirectResponse("/", status_code=303)
    if password != password_confirm:
        return redirect_with("/setup", error="Passwords do not match")
    try:
        account = admin_store.complete_setup(username, new_username, password)
    except AccountError as exc:
        return redirect_with("/setup", error=str(exc))
    session_manager.revoke_user(username)  # the generated account's sessions end
    audit.append(audit_log_path, {"user": account.username, "client": client_ip(request),
                                  "event": f"first-run setup: renamed {username!r}"})
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        COOKIE_NAME,
        session_manager.create_cookie_value(account),
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return response
