"""Tests for GET /metrics via a real FastAPI TestClient -- confirms the
route itself (auth-free, correct media type, wired to the real helper
dependency) on top of frfw.metrics's own already-tested rendering logic
(see tests/test_metrics.py)."""

from __future__ import annotations

import re


def test_metrics_endpoint_requires_no_login(client):
    """Unlike every other route in this webUI, /metrics must be reachable
    with zero cookies/session -- a Prometheus scrape target."""
    response = client.get("/metrics")
    assert response.status_code == 200


def test_metrics_content_type_is_prometheus_text_format(client):
    response = client.get("/metrics")
    assert response.headers["content-type"].startswith("text/plain; version=0.0.4")


def test_metrics_output_contains_help_and_type_annotations(client):
    response = client.get("/metrics")
    assert "# HELP fros_hw_cpu_info" in response.text
    assert "# TYPE fros_hw_cpu_info gauge" in response.text


def test_metrics_output_contains_every_requested_metric_name(logged_in_client):
    # Config-dependent families (interface bytes, XDP status) only ever
    # appear once there's a valid config on disk with at least one
    # interface -- exactly like every other webUI screen that reads
    # parse_config's output, see test_metrics_survives_invalid_config_on_disk
    # below for the "no valid config yet" case.
    logged_in_client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )
    response = logged_in_client.get("/metrics")
    expected_names = [
        "fros_interface_bytes_total",
        "fros_xdp_status",
        "fros_xdp_blocked_connections_total",
        "fros_adblock_total_domains",
        "fros_ztna_active_sessions",
        "fros_bruteforce_banned_ips",
        "fros_ai_ids_quarantined_hosts",
        "fros_hw_cpu_info",
        "fros_hw_cpu_usage_ratio",
        "fros_hw_cpu_mhz",
        "fros_hw_ram_info",
        "fros_hw_ram_usage_bytes",
        "fros_hw_ram_total_bytes",
        "fros_hw_storage_info",
        "fros_hw_storage_usage_bytes",
        "fros_hw_storage_total_bytes",
    ]
    for name in expected_names:
        assert f"# HELP {name} " in response.text, f"missing HELP for {name}"
        assert f"# TYPE {name} " in response.text, f"missing TYPE for {name}"


def test_metrics_reflects_live_helper_state(logged_in_client, webui_env):
    logged_in_client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )
    webui_env["helper"].quarantined["10.0.0.9"] = 100
    webui_env["helper"].banned_ips["10.0.0.5"] = 200
    webui_env["helper"].ztna_sessions["10.0.0.6"] = 300
    webui_env["helper"].ram_modules = [{"part_number": "ABC-123", "speed_mhz": 3200}]

    response = logged_in_client.get("/metrics")

    assert "fros_ai_ids_quarantined_hosts 1" in response.text
    assert "fros_bruteforce_banned_ips 1" in response.text
    assert "fros_ztna_active_sessions 1" in response.text
    assert 'fros_hw_ram_info{model="ABC-123",speed_mhz="3200"} 1' in response.text


def test_metrics_survives_invalid_config_on_disk(client, webui_env):
    # Valid YAML, but fails frfw.config schema validation (no
    # 'interfaces'/'zones') -- the realistic "config currently doesn't
    # pass validation" case every other screen already handles the same
    # way (see e.g. dashboard.py's own parse_config try/except).
    webui_env["config_path"].write_text("version: 1\nhostname: incomplete\n")
    response = client.get("/metrics")
    assert response.status_code == 200
    # Hardware metrics (config-independent) are still present.
    assert "fros_hw_cpu_info" in response.text
    # Config-dependent metrics are simply absent, not a crash.
    assert "fros_interface_bytes_total" not in response.text


_SAMPLE_LINE_RE = re.compile(
    r'^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[a-zA-Z_][a-zA-Z0-9_]*="[^"]*"(,[a-zA-Z_][a-zA-Z0-9_]*="[^"]*")*\})? '
    r"[-+]?[0-9]+(\.[0-9]+)?$"
)


def test_metrics_every_non_comment_line_is_a_well_formed_sample(client):
    response = client.get("/metrics")
    for line in response.text.splitlines():
        if line.startswith("#"):
            continue
        assert _SAMPLE_LINE_RE.match(line), f"malformed Prometheus sample line: {line!r}"
