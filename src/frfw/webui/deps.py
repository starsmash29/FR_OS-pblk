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


def get_iot_scan_options(request: Request) -> dict:
    return request.app.state.iot_scan_options


def get_appid_usage_path(request: Request) -> Path:
    return request.app.state.appid_usage_path


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
VIEWER_ALLOWED_PATHS = frozenset({"/logout", "/account/password"})


def require_login(
    request: Request,
    session_manager: SessionManager = Depends(get_session_manager),
    admin_store: AdminStore = Depends(get_admin_store),
) -> str:
    """Every protected route depends on this. It re-reads the account on
    each request (so a deleted account, a changed role or password counts
    immediately), records it on `request.state.user` for templates and the
    audit log, and enforces the role in one place: a viewer may only use
    safe methods, plus VIEWER_ALLOWED_PATHS. Keeping the check here, not in
    each route, is what makes it impossible to forget on a new POST route
    -- tests/webui/test_rbac.py walks every registered route to prove it."""
    session = session_manager.session_from_cookie(request.cookies.get(COOKIE_NAME))
    account = admin_store.get(session[0]) if session else None
    if account is None or session[1] != account.session_version():
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"}
        )
    request.state.user = account
    if (
        not account.is_admin
        and request.method not in _SAFE_METHODS
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
