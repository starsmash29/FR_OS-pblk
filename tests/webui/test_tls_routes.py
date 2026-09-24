"""Route tests for the /tls screen and its metrics (phase 19)."""

from __future__ import annotations

import json
import time

import yaml

FP = "t13d1516h2_8daaf6152771_e5627efa2ab1"


def _write_config(webui_env, *, xdp_on=True, **tls):
    config = {
        "version": 1, "hostname": "router",
        "zones": {"wan": {}, "lan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"}, "lan": {"device": "eth1", "zone": "lan"}},
        "rules": [], "nat": {"masquerade": [{"out_zone": "wan"}]},
    }
    if xdp_on:
        config["xdp_sni_filter"] = {"enabled": True, "interfaces": ["lan"]}
    if tls:
        config["tls_fingerprint"] = tls
    webui_env["config_path"].write_text(yaml.safe_dump(config))


def _saved(webui_env) -> dict:
    return yaml.safe_load(webui_env["config_path"].read_text()).get("tls_fingerprint", {})


def _state(webui_env):
    now = time.time()
    webui_env["tlsfp_state_path"].write_text(json.dumps({
        "generated": now, "learning": False, "stats": {"hellos": 5, "parse_errors": 0},
        "clients": {"10.0.1.50": {FP: {"first_seen": now, "last_seen": now, "count": 5,
                                       "ja3": ["a" * 32, "b" * 32], "sni": ["www.example.com"]}}},
        "events": [{"ts": now, "type": "new_fingerprint", "client": "10.0.1.50", "ja4": FP, "sni": "www.example.com"}],
    }))


def test_tls_page_shows_inventory_and_events(logged_in_client, webui_env):
    _write_config(webui_env, enabled=True)
    _state(webui_env)
    webui_env["iot_inventory_path"].write_text(json.dumps(
        {"devices": [{"ip": "10.0.1.50", "mac": "aa:bb:cc:dd:ee:01", "hostname": "kids-tablet"}]}))
    page = logged_in_client.get("/tls")
    assert page.status_code == 200
    text = page.text
    assert FP in text and "kids-tablet" in text and "2 variants" in text
    assert "new fingerprint" in text and "www.example.com" in text


def test_block_and_unblock_a_fingerprint(logged_in_client, webui_env):
    _write_config(webui_env, enabled=True)
    r = logged_in_client.post("/tls/block", data={"fingerprint": FP.upper(), "label": "unknown tool"})
    assert "success=" in r.headers["location"]
    assert _saved(webui_env)["blocklist"] == [{"fingerprint": FP, "label": "unknown tool"}]
    r = logged_in_client.post("/tls/block", data={"fingerprint": "nonsense"})
    assert "error=" in r.headers["location"]
    logged_in_client.post("/tls/unblock", data={"fingerprint": FP})
    assert _saved(webui_env)["blocklist"] == []


def test_enabling_needs_the_xdp_filter(logged_in_client, webui_env):
    _write_config(webui_env, xdp_on=False)
    r = logged_in_client.post("/tls/settings", data={"enabled": "true"})
    assert "error=" in r.headers["location"]
    _write_config(webui_env, xdp_on=True)
    r = logged_in_client.post("/tls/settings", data={"enabled": "true", "quarantine_on_match": "true"})
    assert "success=" in r.headers["location"]
    assert _saved(webui_env)["quarantine_on_match"] is True


def test_metrics_report_fingerprints(logged_in_client, webui_env):
    _write_config(webui_env, enabled=True)
    _state(webui_env)
    text = logged_in_client.get("/metrics").text
    assert "fros_tls_fingerprinted_clients 1" in text
    assert "fros_tls_distinct_fingerprints 1" in text
    assert 'fros_tls_fingerprint_events_24h{type="new_fingerprint"} 1' in text
