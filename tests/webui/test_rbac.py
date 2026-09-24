"""Phase 18: accounts with roles, enforced for every route.

The central guarantee -- a viewer can't change anything -- is checked by
walking *every* route the app registers, not a hand-picked list, so a new
POST route added later without the role check fails here.
"""

from __future__ import annotations

import json

import pytest
import yaml
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from frfw.admin_account import AccountError, AdminStore
from frfw.webui.app import create_app
from frfw.webui.deps import VIEWER_ALLOWED_PATHS

#: Unsafe-method routes that are *meant* to work without an admin session.
PUBLIC_CHANGE_ROUTES = {"/login", "/logout", "/ztna/login"}

_CONFIG = {
    "version": 1,
    "hostname": "router",
    "zones": {"wan": {}, "lan": {}},
    "interfaces": {"wan": {"device": "eth0", "zone": "wan"}, "lan": {"device": "eth1", "zone": "lan"}},
    "rules": [{"name": "lan-out", "action": "accept", "from_zone": "lan", "to_zone": "wan"}],
    "nat": {"masquerade": [{"out_zone": "wan"}]},
}


@pytest.fixture
def env(webui_env):
    webui_env["config_path"].write_text(yaml.safe_dump(_CONFIG))
    store = webui_env["admin_store"]
    store.set_password("boss", "adminpass1", "admin")
    store.add_user("guest", "viewerpass1", "viewer")
    return webui_env


def _client(env, username, password) -> TestClient:
    client = TestClient(create_app(**env), follow_redirects=False)
    response = client.post("/login", data={"username": username, "password": password})
    assert response.status_code == 303 and response.headers["location"] == "/", response.headers
    return client


def _api_routes(routes):
    """Every APIRoute, also inside included routers (newer FastAPI wraps
    each include_router() in an object holding the original router)."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        elif hasattr(route, "original_router"):
            yield from _api_routes(route.original_router.routes)


def _unsafe_routes(app) -> list[tuple[str, str]]:
    out = {
        (method, route.path)
        for route in _api_routes(app.routes)
        for method in route.methods - {"GET", "HEAD", "OPTIONS"}
    }
    # Cross-check with the OpenAPI schema, a second, independent listing.
    documented = {
        (method.upper(), path)
        for path, ops in app.openapi()["paths"].items()
        for method in ops
        if method.upper() not in {"GET", "HEAD", "OPTIONS"}
    }
    assert out == documented, out ^ documented
    return sorted(out)


def test_every_change_route_refuses_a_viewer(env):
    viewer = _client(env, "guest", "viewerpass1")
    config_before = env["config_path"].read_text()
    auth_before = env["admin_store"].path.read_text()
    checked = 0
    for method, path in _unsafe_routes(viewer.app):
        if path in PUBLIC_CHANGE_ROUTES or path in VIEWER_ALLOWED_PATHS:
            continue
        concrete = path.replace("{", "").replace("}", "")  # e.g. /users/{target}/delete -> /users/target/delete
        response = viewer.request(method, concrete, data={"name": "x", "enabled": "true"})
        assert response.status_code == 403, (method, path, response.status_code)
        checked += 1
    assert checked >= 30  # really walked the app (35 change routes in phase 18), not an empty list
    assert env["config_path"].read_text() == config_before
    assert env["admin_store"].path.read_text() == auth_before
    assert env["helper"].refresh_adblock_calls == 0 and env["helper"].iot_sync_calls == []


def test_the_public_change_routes_are_exactly_the_expected_ones(env):
    app = create_app(**env)
    anonymous = TestClient(app, follow_redirects=False)
    unprotected = set()
    for method, path in _unsafe_routes(app):
        concrete = path.replace("{", "").replace("}", "")
        response = anonymous.request(method, concrete, data={})
        # A protected route sends an anonymous caller to /login.
        if not (response.status_code == 303 and response.headers.get("location") == "/login"):
            unprotected.add(path)
    assert unprotected <= PUBLIC_CHANGE_ROUTES | {"/logout"}, unprotected


def test_viewer_sees_pages_but_not_account_management(env):
    viewer = _client(env, "guest", "viewerpass1")
    for page in ("/", "/rules", "/interfaces", "/nat", "/dhcp", "/iot", "/apps", "/adblock", "/account"):
        response = viewer.get(page)
        assert response.status_code == 200, page
    page = viewer.get("/rules").text
    assert "role-viewer" in page and "Read-only account" in page
    assert viewer.get("/users").status_code == 403
    assert 'href="/users"' not in page


def test_admin_manages_accounts_and_the_audit_log_records_it(env):
    admin = _client(env, "boss", "adminpass1")
    assert admin.post("/users/add", data={"new_username": "tech", "new_password": "techpass12", "role": "viewer"}).status_code == 303
    assert env["admin_store"].get("tech").role == "viewer"
    admin.post("/users/tech/role", data={"role": "admin"})
    assert env["admin_store"].get("tech").is_admin

    response = admin.post("/users/boss/delete")
    assert "success" in response.headers["location"]  # tech is an admin now, so boss may go
    page = admin.get("/users")
    assert page.status_code == 303  # boss no longer exists: the open session ended

    log = [json.loads(l) for l in env["audit_log_path"].read_text().splitlines()]
    events = [(e.get("user"), e.get("event") or f"{e['method']} {e['path']}", e.get("status")) for e in log]
    assert ("boss", "login", None) in events
    assert ("boss", "POST /users/add", 303) in events
    assert ("boss", "POST /users/boss/delete", 303) in events
    assert "techpass12" not in env["audit_log_path"].read_text()


def test_viewer_attempts_are_audited_as_denied(env):
    viewer = _client(env, "guest", "viewerpass1")
    viewer.post("/rules/add", data={"name": "evil", "action": "accept"})
    last = json.loads(env["audit_log_path"].read_text().splitlines()[-1])
    assert (last["user"], last["path"], last["status"]) == ("guest", "/rules/add", 403)


def test_failed_logins_are_audited(env):
    client = TestClient(create_app(**env), follow_redirects=False)
    client.post("/login", data={"username": "guest", "password": "nope"})
    last = json.loads(env["audit_log_path"].read_text().splitlines()[-1])
    assert (last["user"], last["event"]) == ("guest", "login failed")


def test_last_admin_cannot_be_removed_or_demoted_from_the_ui(env):
    admin = _client(env, "boss", "adminpass1")
    assert "error=" in admin.post("/users/boss/role", data={"role": "viewer"}).headers["location"]
    assert "error=" in admin.post("/users/boss/delete").headers["location"]
    assert env["admin_store"].get("boss").is_admin


def test_role_and_password_changes_apply_to_open_sessions(env):
    viewer = _client(env, "guest", "viewerpass1")
    other_viewer_session = _client(env, "guest", "viewerpass1")
    admin = _client(env, "boss", "adminpass1")

    admin.post("/users/guest/role", data={"role": "admin"})
    # Same cookie, new role: the change is picked up on the next request.
    assert viewer.get("/users").status_code == 200

    response = viewer.post("/account/password", data={
        "current_password": "viewerpass1", "new_password": "newsecret99", "new_password_confirm": "newsecret99",
    })
    assert response.status_code == 303 and "success" in response.headers["location"]
    assert viewer.get("/account").status_code == 200           # this session got a fresh cookie
    assert other_viewer_session.get("/account").status_code == 303  # the other one ended

    admin.post("/users/guest/password", data={"new_password": "resetpass77"})
    assert viewer.get("/account").status_code == 303


def test_own_password_change_needs_the_current_password(env):
    viewer = _client(env, "guest", "viewerpass1")
    response = viewer.post("/account/password", data={
        "current_password": "wrong", "new_password": "newsecret99", "new_password_confirm": "newsecret99",
    })
    assert "error=" in response.headers["location"]
    assert env["admin_store"].verify("guest", "viewerpass1")


# --- the store itself --------------------------------------------------------------------------


def test_legacy_single_account_file_is_read_as_one_admin(tmp_path):
    from frfw.admin_account import hash_password

    path = tmp_path / "auth.json"
    path.write_text(json.dumps({"username": "admin", "password_hash": hash_password("oldpass123")}))
    store = AdminStore(path)
    account = store.verify("admin", "oldpass123")
    assert account is not None and account.is_admin
    store.add_user("guest", "viewerpass1", "viewer")
    data = json.loads(path.read_text())
    assert data["version"] == 2 and set(data["users"]) == {"admin", "guest"}
    assert store.verify("admin", "oldpass123")


@pytest.mark.parametrize(
    "action, error",
    [
        (lambda s: s.add_user("Bad Name", "longenough1", "viewer"), "Username must"),
        (lambda s: s.add_user("ok", "short", "viewer"), "at least 8"),
        (lambda s: s.add_user("ok", "longenough1", "root"), "Unknown role"),
        (lambda s: s.add_user("boss", "longenough1", "viewer"), "already exists"),
        (lambda s: s.set_role("nobody", "admin"), "No such user"),
        (lambda s: s.delete_user("boss"), "At least one admin"),
    ],
)
def test_store_refusals(tmp_path, action, error):
    store = AdminStore(tmp_path / "auth.json")
    store.set_password("boss", "adminpass1", "admin")
    with pytest.raises(AccountError, match=error):
        action(store)


def test_first_account_must_be_an_admin(tmp_path):
    store = AdminStore(tmp_path / "auth.json")
    with pytest.raises(AccountError, match="At least one admin"):
        store.set_password("guest", "viewerpass1", "viewer")
