"""Security-lessons G10: what fr-update-check.timer found is on every
webUI page -- a red banner for a security release, a plain notice for an
ordinary one, nothing once the update is installed."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from frfw import __version__
from frfw.admin_account import ROLE_ADMIN
from frfw.webui.app import create_app

GOOD = "orchid-lamp-7"
NEWER = "99.0.0"


def _page(env) -> str:
    client = TestClient(create_app(**env), follow_redirects=False)
    assert client.post("/login", data={"username": "boss", "password": GOOD}).headers["location"] == "/"
    return client.get("/rules").text


def _cache(env, **data) -> None:
    env["update_check_path"].write_text(json.dumps({"current_version": __version__, "update_available": True,
                                                    "latest_version": NEWER, "security": False, **data}))


@pytest.fixture
def env(webui_env):
    webui_env["admin_store"].set_password("boss", GOOD, ROLE_ADMIN)
    return webui_env


def test_no_cache_no_banner(env):
    page = _page(env)
    assert "Security update available" not in page and f"FR_OS {NEWER} is available" not in page


def test_a_security_release_is_a_red_banner_on_every_page(env):
    _cache(env, security=True)
    page = _page(env)
    assert f'<div class="flash-error">Security update available: FR_OS {NEWER}.' in page


def test_an_ordinary_release_is_a_quiet_notice(env):
    _cache(env)
    page = _page(env)
    assert f'<div class="notice">FR_OS {NEWER} is available' in page
    assert "Security update available" not in page


def test_once_installed_the_banner_goes(env):
    _cache(env, security=True, current_version="0.0.1")
    assert "Security update available" not in _page(env)


