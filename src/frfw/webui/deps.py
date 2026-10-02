"""Shared FastAPI dependencies: pull per-app state off `request.app.state`
(set by `frfw.webui.app.create_app`) rather than importing singletons, so
tests can spin up multiple independently-configured apps in one process.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import Depends, HTTPException, Request, status

from frfw.webui.auth import COOKIE_NAME, AdminStore, SessionManager
from frfw.webui.auth_rate_limiter import BruteforceGuard
from frfw.webui.config_store import load_raw
from frfw.webui.helper_client import HelperClient, UpdateHelperClient


def get_admin_store(request: Request) -> AdminStore:
    return request.app.state.admin_store


def get_session_manager(request: Request) -> SessionManager:
    return request.app.state.session_manager


def get_helper(request: Request) -> HelperClient:
    return request.app.state.helper


def get_update_helper(request: Request) -> UpdateHelperClient:
    return request.app.state.update_helper


def get_config_path(request: Request) -> Path:
    return request.app.state.config_path


def get_ai_ids_state_path(request: Request) -> Path:
    return request.app.state.ai_ids_state_path


def get_update_state_path(request: Request) -> Path:
    return request.app.state.update_state_path


def get_xdp_state_path(request: Request) -> Path:
    return request.app.state.xdp_state_path


def get_adblock_hosts_path(request: Request) -> Path:
    return request.app.state.adblock_hosts_path


def get_adblock_category_dir(request: Request) -> Path:
    return request.app.state.adblock_category_dir


def get_iot_inventory_path(request: Request) -> Path:
    return request.app.state.iot_inventory_path


def get_appid_usage_path(request: Request) -> Path:
    return request.app.state.appid_usage_path


def get_webui_cert_path(request: Request) -> Path:
    return request.app.state.webui_cert_path


def get_tlsfp_state_path(request: Request) -> Path:
    return request.app.state.tlsfp_state_path


def get_audit_log_path(request: Request) -> Path:
    return request.app.state.audit_log_path


def get_bruteforce_guard(request: Request) -> BruteforceGuard:
    return request.app.state.bruteforce_guard


def get_raw_config(config_path: Path = Depends(get_config_path)) -> dict:
    return load_raw(config_path)


#: Methods that never change anything; everything else is a change.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

#: The only changes a viewer may make (phase 18).
VIEWER_ALLOWED_PATHS = frozenset({
    "/logout", "/account/password", "/account/logout-everywhere",
    # Everyone manages their own second factors (security-lessons G5).
    "/account/mfa/totp", "/account/mfa/webauthn/options", "/account/mfa/webauthn/register", "/account/mfa/remove",
})

#: All an account with a generated password can reach (security-lessons G1).
SETUP_PATHS = frozenset({"/setup", "/logout"})

#: Where a CSRF token may travel (security-lessons R15). Browsers can't set a
#: header on a plain HTML form submit, so the hidden field in `csrf_input` is
#: the path every form uses; the header and the JSON body are for fetch().
CSRF_FIELD = "csrf_token"
CSRF_HEADERS = ("x-csrf-token", "x-csrftoken")


def get_mfa_tickets(request: Request):
    return request.app.state.mfa_tickets


def get_mfa_enrolments(request: Request):
    return request.app.state.mfa_enrolments


async def submitted_csrf_token(request: Request) -> str:
    """The CSRF token this request carries, wherever it was submitted.

    Reads the body at most once: Starlette caches the parsed form and the
    parsed JSON on the request, so a route that declares `Form(...)` fields
    still sees its own values afterwards.
    """
    for header in CSRF_HEADERS:
        value = request.headers.get(header)
        if value:
            return value
    query = request.query_params.get(CSRF_FIELD)
    if query:
        return query
    content_type = request.headers.get("content-type", "").lower()
    try:
        if "application/json" in content_type:
            body = await request.json()
            token = body.get(CSRF_FIELD) if isinstance(body, dict) else None
        else:
            form = await request.form()
            token = form.get(CSRF_FIELD)
    except Exception:  # noqa: BLE001 -- an unparseable body carries no token
        return ""
    return token if isinstance(token, str) else ""


#: What an admin without a second factor can reach while
#: require_mfa_for_admins is on (security-lessons G5).
MFA_ENROL_PREFIX = "/account/mfa"


async def require_login(
    request: Request,
    session_manager: SessionManager = Depends(get_session_manager),
    admin_store: AdminStore = Depends(get_admin_store),
) -> str:
    """Every protected route depends on this. It re-reads the account on
    each request (so a deleted account, a changed role or password counts
    immediately), records it on `request.state.user` for templates and the
    audit log, verifies the session's explicit CSRF token on every
    state-changing request (security-lessons R15), and enforces the role in
    one place: a viewer may only use safe methods, plus VIEWER_ALLOWED_PATHS.
    Keeping the check here, not in each route, is what makes it impossible to
    forget on a new POST route -- tests/webui/test_rbac.py walks every
    registered route to prove it."""
    cookie_value = request.cookies.get(COOKIE_NAME)
    session = session_manager.session_from_cookie(cookie_value)
    account = admin_store.get(session[0]) if session else None
    if account is None or session[1] != account.session_version():
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"}
        )
    request.state.user = account
    # On the template's request.state, so `csrf_input(request)` and the
    # page's meta tag render the token of the session that got here.
    request.state.csrf_token = session_manager.csrf_token_for(cookie_value)
    if account.must_change and request.url.path not in SETUP_PATHS:
        # The generated first-boot account: nothing but the setup step
        # until the admin has chosen their own username and password.
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/setup"}
        )
    if (
        account.is_admin
        and not account.has_mfa
        and not request.url.path.startswith(MFA_ENROL_PREFIX)
        and request.url.path not in SETUP_PATHS
        and admin_store.policy().get("require_mfa_for_admins")
    ):
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER, headers={"Location": MFA_ENROL_PREFIX}
        )
    if request.method not in _SAFE_METHODS:
        # R15: SameSite=Lax on the session cookie already blunts cross-site
        # form posts, but it is a side effect of the cookie, not a decision.
        # The token is derived from the session id with the server's secret
        # key, so an attacker on another origin cannot compute one even if
        # they can read the page.
        if not session_manager.verify_csrf(cookie_value, await submitted_csrf_token(request)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token missing or invalid",
            )
        if (
            not account.is_admin
            and request.url.path not in VIEWER_ALLOWED_PATHS
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This account is read-only (viewer role)",
            )
    return account.username


def require_admin(request: Request, username: str = Depends(require_login)) -> str:
    """For admin-only *pages* (account management): viewers can't even look."""
    if not request.state.user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins only")
    return username
