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


def get_bruteforce_guard(request: Request) -> BruteforceGuard:
    return request.app.state.bruteforce_guard


def get_raw_config(config_path: Path = Depends(get_config_path)) -> dict:
    return load_raw(config_path)


def require_login(
    request: Request, session_manager: SessionManager = Depends(get_session_manager)
) -> str:
    username = session_manager.username_from_cookie(request.cookies.get(COOKIE_NAME))
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"}
        )
    return username
