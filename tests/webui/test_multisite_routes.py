"""Route tests for phase 20's /metrics token and the System screen's
monitoring card."""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest
import yaml

from frfw import __codename__, __version__
from frfw.metrics import generate_metrics_token, hash_metrics_token

requires_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")


def _write(webui_env, **metrics):
    config = {
        "version": 1, "hostname": "router-a", "zones": {"lan": {}},
        "interfaces": {"lan": {"device": "lo", "zone": "lan"}}, "rules": [], "nat": {},
    }
    if metrics:
        config["metrics"] = metrics
    webui_env["config_path"].write_text(yaml.safe_dump(config))


def test_metrics_endpoint_requires_the_token_once_set(client, webui_env):
    token, digest = generate_metrics_token()
    _write(webui_env, site="szeged", token_sha256=digest)
    response = client.get("/metrics")
    assert response.status_code == 401 and response.headers["www-authenticate"].startswith("Bearer")
    assert client.get("/metrics", headers={"Authorization": "Bearer nope"}).status_code == 401
    ok = client.get("/metrics", headers={"Authorization": f"Bearer {token}"})
    assert ok.status_code == 200
    assert 'fros_info{site_name="szeged",hostname="router-a",version="' in ok.text
    assert f'version="{__version__}",codename="{__codename__}"' in ok.text
    assert "fros_config_valid 1" in ok.text


def test_invalid_config_does_not_make_a_protected_endpoint_public(client, webui_env):
    token, digest = generate_metrics_token()
    webui_env["config_path"].write_text(yaml.safe_dump({"version": 1, "hostname": "x", "metrics": {"token_sha256": digest}}))
    assert client.get("/metrics").status_code == 401
    text = client.get("/metrics", headers={"Authorization": f"Bearer {token}"}).text
    assert "fros_config_valid 0" in text and 'site_name="unknown"' in text


def test_metrics_endpoint_stays_public_without_a_token(client, webui_env):
    _write(webui_env)
    text = client.get("/metrics").text
    assert 'site_name="router-a"' in text  # defaults to the hostname


def test_system_card_generates_a_token_once_and_stores_only_its_hash(logged_in_client, webui_env):
    _write(webui_env)
    response = logged_in_client.post("/system/metrics/token", data={"action": "generate"})
    assert response.status_code == 200  # rendered, never redirected with the token in a URL
    token = re.search(r'<code style="user-select:all;">([^<]+)</code>', response.text).group(1)
    stored = yaml.safe_load(webui_env["config_path"].read_text())["metrics"]
    assert stored == {"token_sha256": hash_metrics_token(token)}
    assert token not in webui_env["config_path"].read_text()
    assert token not in logged_in_client.get("/system").text
    assert token not in webui_env["audit_log_path"].read_text()

    logged_in_client.post("/system/metrics/site", data={"site": "budapest"})
    logged_in_client.post("/system/metrics/token", data={"action": "disable"})
    assert yaml.safe_load(webui_env["config_path"].read_text())["metrics"] == {"site": "budapest"}
    assert "error=" in logged_in_client.post("/system/metrics/site", data={"site": "Bad Name"}).headers["location"]


@requires_openssl
def test_certificate_download_and_fingerprint(logged_in_client, webui_env):
    from frfw.webui.tls import ensure_self_signed_cert

    _write(webui_env)
    cert, key = webui_env["webui_cert_path"], webui_env["webui_cert_path"].with_name("key.pem")
    ensure_self_signed_cert(cert, key)
    expected = subprocess.run(["openssl", "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha256"],
                              capture_output=True, text=True).stdout.strip().split("=", 1)[1]
    assert expected in logged_in_client.get("/system").text
    download = logged_in_client.get("/system/cert.pem")
    assert download.status_code == 200 and download.text == cert.read_text()


