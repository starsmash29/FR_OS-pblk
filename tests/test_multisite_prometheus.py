"""Phase 20: a real Prometheus scraping two FR_OS routers.

Two webUI instances (each with its own certificate, metrics token and
site name) are scraped by a real Prometheus using the job layout of
telemetry/prometheus-multisite.yml. Then every query in both Grafana
dashboards is evaluated against the collected data -- a dashboard whose
PromQL doesn't parse, or matches nothing that FR_OS exports, fails here.
A third job with the wrong token must be reported down with a 401.

Skipped unless a `prometheus` binary is on PATH or FROS_PROMETHEUS_BIN
points at one (it is not a dependency of this project).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
PROMETHEUS = os.environ.get("FROS_PROMETHEUS_BIN") or shutil.which("prometheus")

pytestmark = pytest.mark.skipif(
    not PROMETHEUS or shutil.which("openssl") is None, reason="needs a prometheus binary and openssl"
)

_LAUNCHER = """
import sys, uvicorn
from pathlib import Path
from frfw.webui.app import create_app
from frfw.webui.auth import AdminStore, SessionManager
d = Path(sys.argv[1])
app = create_app(config_path=d / "config.yaml", admin_store=AdminStore(d / "auth.json"),
                 session_manager=SessionManager(d / "secret.key"), audit_log_path=d / "audit.log",
                 ai_ids_state_path=d / "ai.json", xdp_state_path=d / "xdp.json",
                 adblock_hosts_path=d / "adblock.hosts", iot_inventory_path=d / "iot.json",
                 appid_usage_path=d / "appid.json", tlsfp_state_path=d / "tls.json",
                 webui_cert_path=d / "cert.pem")
uvicorn.run(app, host="127.0.0.1", port=int(sys.argv[2]), ssl_certfile=str(d / "cert.pem"),
            ssl_keyfile=str(d / "key.pem"), log_level="warning")
"""


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _router(tmp: Path, site: str) -> dict:
    from frfw.metrics import generate_metrics_token
    from frfw.webui.tls import ensure_self_signed_cert

    d = tmp / site
    d.mkdir()
    token, digest = generate_metrics_token()
    config = {
        "version": 1, "hostname": f"router-{site}",
        "zones": {"lan": {}}, "interfaces": {"lan": {"device": "lo", "zone": "lan"}},
        "rules": [], "nat": {}, "metrics": {"site": site, "token_sha256": digest},
    }
    (d / "config.yaml").write_text(yaml.safe_dump(config))
    ensure_self_signed_cert(d / "cert.pem", d / "key.pem", dns_names=[f"router-{site}"])
    (d / "token").write_text(token)
    port = _free_port()
    env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
    proc = subprocess.Popen([sys.executable, "-c", _LAUNCHER, str(d), str(port)], env=env)
    return {"site": site, "dir": d, "port": port, "proc": proc}


def _query(prom_port: int, expr: str) -> dict:
    url = f"http://127.0.0.1:{prom_port}/api/v1/query?" + urllib.parse.urlencode({"query": expr})
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


def _dashboard_exprs(name: str) -> list[str]:
    data = json.loads((REPO / "telemetry" / name).read_text())
    exprs = []
    for panel in data["panels"]:
        for target in panel.get("targets", []):
            exprs.append(target["expr"].replace("$site", ".*"))
    return exprs


def test_prometheus_scrapes_two_sites_and_every_dashboard_query_works(tmp_path):
    routers = [_router(tmp_path, "budapest"), _router(tmp_path, "szeged")]
    # The example config's layout, pointed at the local routers.
    example = yaml.safe_load((REPO / "telemetry" / "prometheus-multisite.yml").read_text())
    template = example["scrape_configs"][0]
    jobs = []
    for r in routers:
        job = json.loads(json.dumps(template))
        job["job_name"] = f"fr_os-{r['site']}"
        job["authorization"]["credentials_file"] = str(r["dir"] / "token")
        job["tls_config"]["ca_file"] = str(r["dir"] / "cert.pem")
        job["static_configs"] = [{"targets": [f"127.0.0.1:{r['port']}"], "labels": {"site": r["site"]}}]
        jobs.append(job)
    wrong = json.loads(json.dumps(jobs[0]))
    wrong["job_name"] = "wrong-token"
    (tmp_path / "wrong.token").write_text("not-the-token")
    wrong["authorization"]["credentials_file"] = str(tmp_path / "wrong.token")
    wrong["static_configs"][0]["labels"]["site"] = "impostor"
    jobs.append(wrong)
    prom_config = {"global": {"scrape_interval": "2s", "scrape_timeout": "2s"}, "scrape_configs": jobs}
    (tmp_path / "prometheus.yml").write_text(yaml.safe_dump(prom_config))

    prom_port = _free_port()
    prometheus = subprocess.Popen(
        [PROMETHEUS, f"--config.file={tmp_path / 'prometheus.yml'}", f"--storage.tsdb.path={tmp_path / 'tsdb'}",
         f"--web.listen-address=127.0.0.1:{prom_port}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 60
        health = {}
        while time.time() < deadline:
            time.sleep(2)
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{prom_port}/api/v1/targets", timeout=5) as resp:
                    targets = json.loads(resp.read())["data"]["activeTargets"]
            except OSError:
                continue
            health = {t["labels"]["job"]: (t["health"], t.get("lastError", "")) for t in targets}
            samples = _query(prom_port, 'count_over_time(up{job="fr_os-szeged"}[1m])')["data"]["result"]
            if health.get("fr_os-budapest", ("",))[0] == "up" and health.get("fr_os-szeged", ("",))[0] == "up" \
                    and samples and float(samples[0]["value"][1]) >= 3:
                break
        assert health["fr_os-budapest"][0] == "up", health
        assert health["fr_os-szeged"][0] == "up", health
        assert health["wrong-token"][0] == "down" and "401" in health["wrong-token"][1], health

        info = _query(prom_port, "fros_info")["data"]["result"]
        assert {(r["metric"]["site"], r["metric"]["site_name"]) for r in info} == {
            ("budapest", "budapest"), ("szeged", "szeged")}

        for name in ("grafana-dashboard.json", "grafana-fleet-dashboard.json"):
            for expr in _dashboard_exprs(name):
                result = _query(prom_port, expr)
                assert result["status"] == "success", (name, expr, result)

        # Panels that must show real data even without the privileged helper.
        must_have = {
            'count(up{job=~"fr_os.*", site=~".*"} == 1) or vector(0)': lambda r: float(r[0]["value"][1]) == 2,
            'max by (site, hostname, version, codename) (fros_info{site=~".*"})':
                lambda r: len(r) == 2 and all(x["metric"]["codename"] for x in r),
            'max by (site) (fros_config_valid{site=~".*"})': lambda r: all(x["value"][1] == "1" for x in r) and len(r) == 2,
            'sum by (site, direction) (irate(fros_interface_bytes_total{site=~".*"}[5m]))': lambda r: len(r) == 4,
            'max by (site) (fros_hw_cpu_usage_ratio{site=~".*"})': lambda r: len(r) == 2,
        }
        fleet_exprs = set(_dashboard_exprs("grafana-fleet-dashboard.json"))
        for expr, check in must_have.items():
            assert expr in fleet_exprs, expr
            result = _query(prom_port, expr)["data"]["result"]
            assert result and check(result), (expr, result)
    finally:
        prometheus.terminate()
        for r in routers:
            r["proc"].terminate()
        prometheus.wait(timeout=10)
        for r in routers:
            r["proc"].wait(timeout=10)


def test_example_config_passes_promtool():
    promtool = Path(PROMETHEUS).with_name("promtool")
    if not promtool.exists():
        pytest.skip("promtool not next to prometheus")
    # credentials/ca files in the example don't exist here; promtool only
    # warns about unreadable files at scrape time, it checks the syntax.
    proc = subprocess.run([str(promtool), "check", "config", "--syntax-only",
                           str(REPO / "telemetry" / "prometheus-multisite.yml")],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
