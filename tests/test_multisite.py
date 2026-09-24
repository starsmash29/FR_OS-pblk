"""Phase 20: multi-site monitoring -- the /metrics token, fros_info, the
metrics config, the CLI, the webUI's monitoring card, the certificate's
subjectAltName, and the shipped dashboards' structure. The real
Prometheus end-to-end check is tests/test_multisite_prometheus.py."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from frfw.config import ConfigError, parse_config
from frfw.metrics import generate_metrics_token, hash_metrics_token, metrics_token_ok

REPO = Path(__file__).resolve().parents[1]
requires_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")


# --- token check -----------------------------------------------------------------------------


def test_token_check():
    token, digest = generate_metrics_token()
    assert len(token) >= 40 and digest == hash_metrics_token(token)
    raw = {"metrics": {"token_sha256": digest}}
    assert metrics_token_ok(raw, f"Bearer {token}")
    assert metrics_token_ok(raw, f"bearer {token}")
    assert not metrics_token_ok(raw, None)
    assert not metrics_token_ok(raw, "Bearer wrong")
    assert not metrics_token_ok(raw, f"Basic {token}")
    assert metrics_token_ok({}, None)                                    # no token configured: public
    assert not metrics_token_ok({"metrics": {"token_sha256": "abc"}}, f"Bearer {token}")  # malformed: closed


def test_metrics_config_validation(minimal_config_dict):
    raw = dict(minimal_config_dict, metrics={"site": "budapest-office", "token_sha256": "a" * 64})
    assert parse_config(raw).metrics.site == "budapest-office"
    for bad, error in (({"site": "Budapest Office"}, "metrics.site"), ({"token_sha256": "xyz"}, "token_sha256")):
        with pytest.raises(ConfigError, match=error):
            parse_config(dict(minimal_config_dict, metrics=bad))


# --- certificate names ---------------------------------------------------------------------------


@requires_openssl
def test_generated_certificate_has_subject_alt_names_and_replaces_only_the_legacy_one(tmp_path):
    from frfw.webui.tls import _is_legacy_auto_cert, ensure_self_signed_cert

    def openssl_cert(name, cn):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", str(tmp_path / f"{name}.key"), "-out", str(tmp_path / f"{name}.pem"),
                        "-subj", f"/CN={cn}"], capture_output=True, check=True)

    openssl_cert("legacy", "fr-router")
    openssl_cert("admin", "router.example.com")
    assert _is_legacy_auto_cert(tmp_path / "legacy.pem") and not _is_legacy_auto_cert(tmp_path / "admin.pem")
    assert ensure_self_signed_cert(tmp_path / "legacy.pem", tmp_path / "legacy.key",
                                   dns_names=["site-a"], ip_addresses=["10.0.0.1"])
    san = subprocess.run(["openssl", "x509", "-in", str(tmp_path / "legacy.pem"), "-noout", "-ext", "subjectAltName"],
                         capture_output=True, text=True).stdout
    assert "DNS:fr-router" in san and "DNS:site-a" in san and "IP Address:10.0.0.1" in san
    admin_before = (tmp_path / "admin.pem").read_text()
    assert not ensure_self_signed_cert(tmp_path / "admin.pem", tmp_path / "admin.key")
    assert (tmp_path / "admin.pem").read_text() == admin_before


# --- CLI ------------------------------------------------------------------------------------------


def test_cli_metrics_token(tmp_path, capsys, minimal_config_dict):
    from frfw.cli import main

    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(minimal_config_dict))
    path.chmod(0o640)
    assert main(["metrics-token", str(path), "--generate", "--site", "szeged"]) == 0
    token = capsys.readouterr().out.strip()
    stored = yaml.safe_load(path.read_text())["metrics"]
    assert stored == {"token_sha256": hash_metrics_token(token), "site": "szeged"}
    assert path.stat().st_mode & 0o777 == 0o640
    assert main(["metrics-token", str(path), "--disable"]) == 0
    assert yaml.safe_load(path.read_text())["metrics"] == {"site": "szeged"}
    assert main(["metrics-token", str(path)]) == 1


# --- dashboards --------------------------------------------------------------------------------------


def _exprs(name):
    data = json.loads((REPO / "telemetry" / name).read_text())
    return data, [t["expr"] for p in data["panels"] for t in p.get("targets", [])]


def test_router_dashboard_filters_every_query_by_site():
    data, exprs = _exprs("grafana-dashboard.json")
    assert data["uid"] == "fr-os-router"
    assert [v["name"] for v in data["templating"]["list"]] == ["site"]
    for expr in exprs:
        for metric in re.findall(r"\b(fros_[a-z0-9_]+)", expr):
            assert re.search(rf'{metric}\{{[^}}]*site=~"\$site"', expr), expr


def test_fleet_dashboard_links_to_the_router_dashboard():
    data, exprs = _exprs("grafana-fleet-dashboard.json")
    assert data["uid"] == "fr-os-fleet" and len(exprs) >= 15
    text = json.dumps(data)
    assert "/d/fr-os-router?var-site=" in text
    assert all('site=~"$site"' in expr for expr in exprs)
