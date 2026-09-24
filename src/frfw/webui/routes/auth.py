from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from frfw.admin_account import ROLE_ADMIN, AccountError, validate_password, validate_username
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
            "first_run": not admin_store.exists(),
            "error": request.query_params.get("error"),
        },
    )


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str | None = Form(None),
    admin_store: AdminStore = Depends(get_admin_store),
    session_manager: SessionManager = Depends(get_session_manager),
    helper: HelperClient = Depends(get_helper),
    guard: BruteforceGuard = Depends(get_bruteforce_guard),
    audit_log_path: Path = Depends(get_audit_log_path),
):
    ip = client_ip(request)
    if not admin_store.exists():
        # First-run account creation, not a login attempt against an
        # existing account -- there is no password to brute-force yet,
        # so this branch is deliberately not rate-limited. The first
        # account is always an admin.
        if password != password_confirm:
            return redirect_with("/login", error="Passwords do not match")
        try:
            validate_username(username)
            validate_password(password)
        except AccountError as exc:
            return redirect_with("/login", error=str(exc))
        admin_store.set_password(username, password, ROLE_ADMIN)
        audit.append(audit_log_path, {"user": username, "client": ip, "event": "first account created"})
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
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE_NAME)
    return response
