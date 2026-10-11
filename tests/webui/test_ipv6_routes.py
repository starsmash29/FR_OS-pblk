"""ROADMAP FND-1a/1b: IPv6 on the Interfaces screen -- the switch, saved
to config.yaml, and what the provider gave and the LAN networks made of
it, as the apply-helper reports it (the webUI itself has no netlink
socket)."""

from __future__ import annotations

import html

import yaml

from frfw.config import load_config

_CONFIG = {
    "version": 1,
    "hostname": "router",
    "zones": {"wan": {}, "lan": {}},
    "interfaces": {"wan": {"device": "eth0", "zone": "wan"}, "lan": {"device": "eth1", "zone": "lan"}},
    "rules": [{"name": "lan-out", "action": "accept", "from_zone": "lan", "to_zone": "wan"}],
    "nat": {"masquerade": [{"out_zone": "wan"}]},
}


def _write(webui_env, **extra):
    webui_env["config_path"].write_text(yaml.safe_dump({**_CONFIG, **extra}))


def test_the_switch_turns_it_on_and_off(logged_in_client, webui_env):
    _write(webui_env)
    page = logged_in_client.get("/interfaces")
    assert 'id="ipv6-summary" data-state="off"' in page.text
    assert 'name="enabled" value="true" >' in page.text  # not checked

    r = logged_in_client.post("/interfaces/ipv6", data={"enabled": "true"})
    assert r.status_code == 303 and "success" in r.headers["location"]
    assert load_config(webui_env["config_path"]).ipv6.enabled is True
    assert 'name="enabled" value="true" checked>' in logged_in_client.get("/interfaces").text

    r = logged_in_client.post("/interfaces/ipv6", data={})
    assert r.status_code == 303 and "success" in r.headers["location"]
    # Off is the default: the section goes, the file stays as it was.
    assert "ipv6" not in yaml.safe_load(webui_env["config_path"].read_text())


def test_turning_it_on_without_a_wan_is_refused(logged_in_client, webui_env):
    _write(webui_env, interfaces={"lan": {"device": "eth1", "zone": "lan"}}, zones={"lan": {}},
           rules=[], nat={})
    r = logged_in_client.post("/interfaces/ipv6", data={"enabled": "true"})
    assert r.status_code == 303 and "error" in r.headers["location"]
    assert load_config(webui_env["config_path"]).ipv6.enabled is False


def test_the_card_shows_what_the_provider_gave(logged_in_client, webui_env):
    _write(webui_env, ipv6={"enabled": True})
    webui_env["helper"].ipv6 = {
        "state": "prefix",
        "summary": "A prefix was delegated: 2001:db8:100::/56 (256 LAN networks).",
        "addresses": [["eth0", "2001:db8:1::5/64", "SLAAC"]],
        "default_routes": [["eth0", "fe80::1"]],
        "prefixes": ["2001:db8:100::/56"],
    }
    text = logged_in_client.get("/interfaces").text
    assert 'data-state="prefix"' in text
    assert '<dd class="ipv6-address">2001:db8:1::5/64 (SLAAC)</dd>' in text
    assert "via fe80::1 on eth0" in text
    assert '<dd class="ipv6-prefix">2001:db8:100::/56</dd>' in text


def test_the_card_shows_the_lan_networks(logged_in_client, webui_env):
    _write(webui_env, ipv6={"enabled": True})
    webui_env["helper"].ipv6 = {
        "state": "prefix", "summary": "A prefix was delegated.", "prefixes": ["2001:db8:100::/56"],
        "lan": [["lan", "eth1", "2001:db8:100::/64"], ["guest", "eth2", ""]],
    }
    text = logged_in_client.get("/interfaces").text
    assert '<dt>lan (eth1)</dt><dd class="ipv6-lan">2001:db8:100::/64</dd>' in text
    assert '<dt>guest (eth2)</dt><dd class="ipv6-lan">no network yet</dd>' in text


def test_the_switch_keeps_the_lan_zones(logged_in_client, webui_env):
    _write(webui_env, ipv6={"enabled": True, "lan_zones": []})
    logged_in_client.post("/interfaces/ipv6", data={})
    assert yaml.safe_load(webui_env["config_path"].read_text())["ipv6"] == {"enabled": False, "lan_zones": []}
    logged_in_client.post("/interfaces/ipv6", data={"enabled": "true"})
    assert load_config(webui_env["config_path"]).ipv6.lan_zones == ()


def test_a_helper_error_is_shown_not_raised(logged_in_client, webui_env):
    _write(webui_env, ipv6={"enabled": True})
    helper = webui_env["helper"]

    def broken():
        return {"ok": False, "message": "could not read the IPv6 state: <boom>"}

    helper.ipv6_status = broken
    text = logged_in_client.get("/interfaces").text
    assert 'data-state="unknown"' in text
    assert html.escape("could not read the IPv6 state: <boom>") in text
