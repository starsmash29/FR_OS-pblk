from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from frfw.admin_account import AccountError, hash_password
from frfw.webui import audit
from frfw.webui.auth import COOKIE_NAME, AdminStore, SessionManager
from frfw.webui.auth_rate_limiter import BruteforceGuard, locked_message, reject_failed_login
from frfw.webui.client_ip import client_ip
from frfw.webui.deps import (
    get_admin_store,
    get_audit_log_path,
    get_bruteforce_guard,
    get_helper,
    get_mfa_tickets,
    get_session_manager,
    require_login,
)
from frfw.webui.helper_client import HelperClient
from frfw.webui.mfa import TICKET_COOKIE, TICKET_SECONDS, TicketStore
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
    mfa_tickets: TicketStore = Depends(get_mfa_tickets),
):
    ip = client_ip(request)
    locked = guard.account_locked(username, ip)
    if locked:
        # Security-lessons G6: too many failures for this account lately.
        # The password isn't even checked (but hashed, for the same timing).
        hash_password(password)
        audit.append(audit_log_path, {"user": username, "client": ip, "event": "login refused: account locked"})
        return redirect_with("/login", error=locked_message(locked))
    account = admin_store.verify(username, password)
    if account is None:
        audit.append(audit_log_path, {"user": username, "client": ip, "event": "login failed"})
        # Counted for any name, existing or not: a lockout mustn't tell
        # which usernames exist.
        return reject_failed_login(ip, guard, helper, redirect_path="/login", account=username)

    if account.has_mfa and mfa_tickets.account_locked(account.username):
        audit.append(audit_log_path, {"user": username, "client": ip, "event": "second factor locked"})
        return redirect_with("/login", error="Too many wrong second-factor attempts for this account -- "
                                             "try again in 15 minutes")
    if account.has_mfa:
        # Security-lessons G5: the password alone gets no session, only a
        # single-use ticket for the second step (frfw.webui.mfa).
        audit.append(audit_log_path, {"user": username, "client": ip, "event": "password ok, second factor pending"})
        response = RedirectResponse("/login/mfa", status_code=303)
        response.set_cookie(TICKET_COOKIE, mfa_tickets.create(account), max_age=TICKET_SECONDS, path="/login",
                            httponly=True, samesite="strict", secure=request.url.scheme == "https")
        return response

    new_source = guard.record_success(ip, account.username)
    audit.append(audit_log_path, {"user": username, "role": account.role, "client": ip, "event": "login",
                                  **({"new_source": True} if new_source else {})})
    if new_source:
        audit.alert(audit_log_path, f"{username!r} signed in from a new address {ip}", user=username, client=ip)
    return issue_session(request, RedirectResponse("/", status_code=303), account, session_manager)


def issue_session(request: Request, response, account, session_manager: SessionManager):
    """Give the browser a fresh session for `account` (on `response`)."""
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
    return issue_session(request, RedirectResponse("/", status_code=303), account, session_manager)
