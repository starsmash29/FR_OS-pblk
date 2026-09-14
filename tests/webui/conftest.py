from __future__ import annotations

import yaml
from fastapi.testclient import TestClient

import pytest

from frfw.config import parse_config
from frfw.webui.app import create_app
from frfw.webui.auth import AdminStore, SessionManager


class FakeHelper:
    """An in-memory stand-in for the real Unix-socket apply-helper.

    Real save_config semantics (validate-then-write) without a running
    daemon or socket -- exactly what the real helper does, just in-process,
    so route tests exercise the same validation path production traffic
    would hit.
    """

    def __init__(self, config_path):
        self.config_path = config_path
        self.applied = []
        self.rolled_back = False

    def ping(self):
        return {"ok": True, "message": "pong"}

    def save_config(self, yaml_text: str) -> dict:
        try:
            parse_config(yaml.safe_load(yaml_text))
        except Exception as exc:  # noqa: BLE001 -- mirrors the real helper's catch-all
            return {"ok": False, "message": str(exc)}
        self.config_path.write_text(yaml_text)
        return {"ok": True, "message": f"Config saved to {self.config_path}"}

    def apply(self, dry_run: bool = False) -> dict:
        self.applied.append(dry_run)
        return {"ok": True, "message": "dry-run ok" if dry_run else "applied"}

    def rollback(self) -> dict:
        self.rolled_back = True
        return {"ok": True, "message": "rolled back"}


@pytest.fixture
def webui_env(tmp_path):
    config_path = tmp_path / "config.yaml"
    return {
        "config_path": config_path,
        "admin_store": AdminStore(tmp_path / "auth.json"),
        "session_manager": SessionManager(tmp_path / "secret.key"),
        "helper": FakeHelper(config_path),
        "ai_ids_state_path": tmp_path / "ai_ids_state.json",
    }


@pytest.fixture
def app(webui_env):
    return create_app(**webui_env)


@pytest.fixture
def client(app):
    return TestClient(app, follow_redirects=False)


@pytest.fixture
def logged_in_client(client, webui_env):
    webui_env["admin_store"].set_password("admin", "hunter22")
    response = client.post("/login", data={"username": "admin", "password": "hunter22"})
    assert response.status_code == 303
    return client
