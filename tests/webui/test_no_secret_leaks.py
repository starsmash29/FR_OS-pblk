"""Security-lessons G3: secrets never leave the box through the webUI.

FortiBleed attackers exported configuration backups and cracked the
admin hashes in them offline. Every page and API response the webUI can
produce is rendered here -- as an admin and as a viewer -- against a
router whose config and state hold every kind of secret FR_OS keeps, and
none of them may appear: account and ZTNA password hashes (or their salts
and digests), the /metrics token and its digest, the session-signing key,
the TLS private key, second-factor secrets.
"""

from __future__ import annotations

import base64

import pytest
import yaml
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from frfw.admin_account import hash_password
from frfw.metrics import generate_metrics_token
from frfw.webui.app import create_app

#: Routes that never end on their own (a live log stream) or aren't pages.
SKIP = {"/xdp/logs/stream", "/logout"}

FAKE_TLS_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----\n"


@pytest.fixture
def secrets_everywhere(webui_env, tmp_path):
    token, digest = generate_metrics_token()
    ztna_hash = hash_password("alice-pass-1")
    webui_env["config_path"].write_text(yaml.safe_dump({
        "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"},
                       "lan": {"device": "eth1", "zone": "lan", "address": "192.168.1.1/24"}},
        "rules": [], "nat": {"masquerade": [{"out_zone": "wan"}]},
        "ztna": {"enabled": True, "users": [{"username": "alice", "password_hash": ztna_hash}]},
        "metrics": {"token_sha256": digest},
    }))
    store = webui_env["admin_store"]
    store.set_password("boss", "adminpass1", "admin")
    store.add_user("guest", "viewerpass1", "viewer")
    # An account with second factors (security-lessons G5): its TOTP secret
    # and security-key public key are secrets too.
    store.add_user("carol", "mint-ribbon-5", "admin")
    store.set_mfa("carol", {"totp": {"secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "last_step": 1},
                            "webauthn": [{"id": "Y3JlZC1pZA", "public_key": "pQECAyYgASFYIGNhcm9sLXB1YmxpYy1rZXk",
                                          "sign_count": 3, "rp_id": "fr-router.lan", "name": "yubi", "added": 0}]})
    (tmp_path / "key.pem").write_text(FAKE_TLS_KEY)
    webui_env["webui_cert_path"].write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")

    secret_key = webui_env["session_manager"]  # created the key file on construction
    key_bytes = (tmp_path / "secret.key").read_bytes()
    forbidden = {"metrics token": token, "metrics token digest": digest, "TLS private key": "PRIVATE KEY",
                 "session key (hex)": key_bytes.hex(), "session key (base64)": base64.b64encode(key_bytes).decode()}
    forbidden["TOTP secret"] = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    forbidden["security-key public key"] = "pQECAyYgASFYIGNhcm9sLXB1YmxpYy1rZXk"
    for label, stored in (("ZTNA hash", ztna_hash), ("boss hash", store.get("boss").password_hash),
                          ("guest hash", store.get("guest").password_hash)):
        algorithm, *_params, salt, digest_hex = stored.split("$")
        forbidden[label] = stored
        forbidden[f"{label} salt"] = salt
        forbidden[f"{label} digest"] = digest_hex
    assert secret_key is not None
    return forbidden, token


def _get_routes(app) -> list[str]:
    def walk(routes):
        for route in routes:
            if isinstance(route, APIRoute):
                yield route
            elif hasattr(route, "original_router"):
                yield from walk(route.original_router.routes)
    return sorted({r.path for r in walk(app.routes) if "GET" in r.methods and "{" not in r.path} - SKIP)


def _signed_in(app, username, password) -> TestClient:
    client = TestClient(app, follow_redirects=False)
    assert client.post("/login", data={"username": username, "password": password}).headers["location"] == "/"
    return client


@pytest.mark.parametrize("who", [("boss", "adminpass1"), ("guest", "viewerpass1"), None])
def test_no_page_or_api_response_contains_a_secret(webui_env, secrets_everywhere, who):
    forbidden, token = secrets_everywhere
    app = create_app(**webui_env)
    client = _signed_in(app, *who) if who else TestClient(app, follow_redirects=False)
    paths = _get_routes(app)
    assert "/ztna" in paths and "/users" in paths and "/system" in paths and "/metrics" in paths
    for path in paths:
        headers = {"Authorization": f"Bearer {token}"} if path == "/metrics" else {}
        response = client.get(path, headers=headers)
        body = response.text + "".join(f"{k}: {v}\n" for k, v in response.headers.items())
        for label, secret in forbidden.items():
            assert secret not in body, f"{path} leaks the {label}"


def test_the_certificate_download_is_only_the_certificate(webui_env, secrets_everywhere):
    app = create_app(**webui_env)
    body = _signed_in(app, "boss", "adminpass1").get("/system/cert.pem").text
    assert "BEGIN CERTIFICATE" in body and "PRIVATE KEY" not in body


def test_the_csrf_token_stays_in_the_form_and_the_meta_tag(webui_env, secrets_everywhere):
    """R15: the token is a session credential, so it belongs in the hidden
    field and the page's own meta tag and nowhere else. An access log, an
    audit line or an error page that carries it would hand it to whoever can
    read those files."""
    from frfw.webui.auth import COOKIE_NAME

    app = create_app(**webui_env)
    client = _signed_in(app, "boss", "adminpass1")
    token = app.state.session_manager.csrf_token_for(client.cookies.get(COOKIE_NAME))
    assert token

    carriers = (f'name="csrf_token" value="{token}"', f'content="{token}"')

    # Every page the admin can reach, not just one: the token may only ever
    # sit inside the meta tag or a hidden field of a form that posts.
    for path in _get_routes(app):
        body = client.get(path, headers={"X-CSRF-Token": token}).text
        if token in body:
            assert body.count(token) == body.count(carriers[0]) + body.count(carriers[1]), path

    # Not in the audit log of a change request that carried it in the header.
    client.post("/adblock/refresh", headers={"X-CSRF-Token": token})
    assert token not in webui_env["audit_log_path"].read_text()

    # And not in a response that has no form to put it in.
    assert token not in client.get("/no-such-page").text


# -- files and exports ------------------------------------------------------------------


def test_the_account_file_is_owner_only(tmp_path):
    import stat

    from frfw.admin_account import AdminStore

    store = AdminStore(tmp_path / "auth.json")
    store.set_password("boss", "adminpass1", "admin")
    assert stat.S_IMODE((tmp_path / "auth.json").stat().st_mode) == 0o600


def test_the_config_export_carries_no_secret(webui_env, secrets_everywhere, capsys):
    from frfw import cli
    from frfw.admin_account import verify_password
    from frfw.config import parse_config
    from frfw.config.export import REMOVED

    forbidden, _token = secrets_everywhere
    assert cli.main(["config-export", str(webui_env["config_path"])]) == 0
    exported = capsys.readouterr().out
    for label, secret in forbidden.items():
        assert secret not in exported, f"the export leaks the {label}"
    # Still a valid config -- and the placeholder can never sign anyone in.
    config = parse_config(yaml.safe_load(exported))
    assert config.ztna.users[0].password_hash == REMOVED
    assert not verify_password("alice-pass-1", REMOVED)
    assert config.metrics.token_sha256 is None
