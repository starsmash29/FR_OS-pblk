from __future__ import annotations

from frfw.adblock import write_hosts_file
from frfw.config import load_config


def _seed_interface(client):
    # frfw.config.loader requires at least one interface for *any* config
    # to validate at all -- same pattern as test_ztna_routes.py's helper.
    client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )


def test_adblock_page_requires_login(client):
    response = client.get("/adblock")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_adblock_page_shows_disabled_by_default(logged_in_client):
    response = logged_in_client.get("/adblock")
    assert response.status_code == 200
    assert "Disabled" in response.text
    assert "badge-red" in response.text


def test_adblock_page_shows_live_domain_count(logged_in_client, webui_env):
    write_hosts_file({"a.example.com", "b.example.com"}, webui_env["adblock_hosts_path"])
    response = logged_in_client.get("/adblock")
    assert response.status_code == 200
    assert "<dd>2</dd>" in response.text


def test_save_settings_persists_enabled_and_source_urls(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    response = logged_in_client.post(
        "/adblock/settings",
        data={
            "enabled": "true",
            "source_urls": "https://a.example/hosts\nhttps://b.example/hosts",
            "xdp_critical_limit": 25,
        },
    )
    assert "success" in response.headers["location"]

    config = load_config(webui_env["config_path"])
    assert config.adblocker.enabled is True
    assert config.adblocker.source_urls == ["https://a.example/hosts", "https://b.example/hosts"]
    assert config.adblocker.xdp_critical_limit == 25


def test_save_settings_dedupes_and_strips_urls(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    logged_in_client.post(
        "/adblock/settings",
        data={
            "source_urls": "https://a.example/hosts\n\nhttps://a.example/hosts\n  \n",
            "xdp_critical_limit": 0,
        },
    )
    config = load_config(webui_env["config_path"])
    assert config.adblocker.source_urls == ["https://a.example/hosts"]


def test_save_settings_can_disable_again(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    logged_in_client.post(
        "/adblock/settings",
        data={"enabled": "true", "source_urls": "https://a.example/hosts"},
    )
    logged_in_client.post("/adblock/settings", data={"enabled": "false", "source_urls": ""})

    config = load_config(webui_env["config_path"])
    assert config.adblocker.enabled is False


def test_save_settings_rejects_invalid_url(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    response = logged_in_client.post(
        "/adblock/settings", data={"source_urls": "not-a-valid-url"}
    )
    assert "error" in response.headers["location"]


def test_refresh_now_success(logged_in_client, webui_env):
    response = logged_in_client.post("/adblock/refresh")
    assert "success" in response.headers["location"]
    assert webui_env["helper"].refresh_adblock_calls == 1


def test_refresh_now_failure(logged_in_client, webui_env):
    webui_env["helper"].refresh_adblock_result = {"ok": False, "message": "all sources failed"}
    response = logged_in_client.post("/adblock/refresh")
    assert "error" in response.headers["location"]
    assert "all+sources+failed" in response.headers["location"]


# --- phase 15: categories, allowlist, LAN DNS ----------------------------------


def _write_dhcp_config(webui_env, adblocker=None):
    import yaml

    config = {
        "version": 1,
        "hostname": "router",
        "zones": {"wan": {}, "lan": {}},
        "interfaces": {
            "wan": {"device": "eth0", "zone": "wan"},
            "lan": {"device": "eth1", "zone": "lan", "address": "10.0.1.1/24"},
        },
        "rules": [],
        "nat": {"masquerade": [{"out_zone": "wan"}]},
        "dhcp": {"lan": {"range_start": "10.0.1.100", "range_end": "10.0.1.200", "dns_servers": ["9.9.9.9"]}},
    }
    if adblocker is not None:
        config["adblocker"] = adblocker
    webui_env["config_path"].write_text(yaml.safe_dump(config))


def test_save_presets_allowlist_and_lan_dns_flags(logged_in_client, webui_env):
    from frfw.adblock.categories import PRESETS_BY_NAME

    _write_dhcp_config(webui_env)
    response = logged_in_client.post(
        "/adblock/settings",
        data={
            "enabled": "true",
            "source_urls": "",
            "categories": ["malware", "phishing"],
            "allowlist": "Good.Example\nother.example",
            "serve_lan": "true",
            "force_dns": "true",
            "query_logging": "true",
        },
    )
    assert "success" in response.headers["location"]
    config = load_config(webui_env["config_path"])
    assert config.adblocker.categories == {
        "malware": list(PRESETS_BY_NAME["malware"].urls),
        "phishing": list(PRESETS_BY_NAME["phishing"].urls),
    }
    assert config.adblocker.allowlist == ["good.example", "other.example"]
    assert config.adblocker.serve_lan and config.adblocker.force_dns and config.adblocker.query_logging


def test_save_keeps_hand_added_categories_and_edited_preset_urls(logged_in_client, webui_env):
    _write_dhcp_config(
        webui_env,
        {
            "enabled": True,
            "categories": {
                "malware": ["https://mirror.example/malware.txt"],  # admin-edited preset URL
                "crypto": ["https://lists.example/crypto.txt"],  # hand-added, not a preset
            },
        },
    )
    logged_in_client.post("/adblock/settings", data={"enabled": "true", "categories": ["malware"]})
    config = load_config(webui_env["config_path"])
    assert config.adblocker.categories == {
        "malware": ["https://mirror.example/malware.txt"],
        "crypto": ["https://lists.example/crypto.txt"],
    }
    page = logged_in_client.get("/adblock").text
    assert "crypto" in page and "lists.example/crypto.txt" in page


def test_unknown_category_and_invalid_combination_are_rejected(logged_in_client, webui_env):
    _write_dhcp_config(webui_env)
    bad = logged_in_client.post("/adblock/settings", data={"enabled": "true", "categories": ["weather"]})
    assert "error=" in bad.headers["location"]
    no_serve = logged_in_client.post(
        "/adblock/settings", data={"enabled": "true", "categories": ["malware"], "force_dns": "true"}
    )
    assert "error=" in no_serve.headers["location"]


def test_page_shows_per_category_counts(logged_in_client, webui_env):
    _write_dhcp_config(webui_env, {"enabled": True, "categories": {"malware": ["https://x.example/m"]}})
    write_hosts_file({"a.example"}, webui_env["adblock_hosts_path"])
    write_hosts_file({"b.example", "c.example"}, webui_env["adblock_category_dir"] / "malware.hosts")
    page = logged_in_client.get("/adblock").text
    assert "<dt>malware</dt><dd>2</dd>" in page
    assert "<dt>ads</dt><dd>1</dd>" in page
    assert "<dd>3</dd>" in page  # total


def test_metrics_report_blocked_domains_per_category(client, webui_env, scrape):
    _write_dhcp_config(webui_env, {"enabled": True, "categories": {"malware": ["https://x.example/m"]}})
    write_hosts_file({"b.example", "c.example"}, webui_env["adblock_category_dir"] / "malware.hosts")
    text = scrape(client).text
    assert "# TYPE fros_dns_blocked_domains gauge" in text
    assert 'fros_dns_blocked_domains{category="malware"} 2' in text
    assert 'fros_dns_blocked_domains{category="ads"} 0' in text


# --- local names (ROADMAP DNS-1) ---------------------------------------------


def _serving_lan(webui_env, dhcp_config_dict):
    import yaml

    dhcp_config_dict["adblocker"] = {"enabled": True, "source_urls": ["https://a.example/hosts"], "serve_lan": True}
    webui_env["config_path"].write_text(yaml.safe_dump(dhcp_config_dict))


def test_local_names_are_added_listed_and_removed(logged_in_client, webui_env, dhcp_config_dict):
    _serving_lan(webui_env, dhcp_config_dict)
    response = logged_in_client.post("/adblock/local-dns/add",
                                     data={"kind": "hosts", "name": "NAS.lan.", "address": "10.0.0.20"})
    assert "success" in response.headers["location"]
    logged_in_client.post("/adblock/local-dns/add",
                          data={"kind": "overrides", "name": "intranet.example.com", "address": "10.0.0.30"})
    logged_in_client.post("/adblock/local-dns/domain", data={"domain": "lan"})
    config = load_config(webui_env["config_path"])
    assert config.local_dns.hosts == {"nas.lan": "10.0.0.20"}
    assert config.local_dns.overrides == {"intranet.example.com": "10.0.0.30"}
    assert config.local_dns.domain == "lan"

    page = logged_in_client.get("/adblock").text
    assert "<code>nas.lan</code>" in page and "10.0.0.30" in page and 'value="lan"' in page

    logged_in_client.post("/adblock/local-dns/remove", data={"kind": "hosts", "name": "nas.lan"})
    logged_in_client.post("/adblock/local-dns/remove", data={"kind": "overrides", "name": "intranet.example.com"})
    logged_in_client.post("/adblock/local-dns/domain", data={"domain": ""})
    assert load_config(webui_env["config_path"]).local_dns.names() == []
    assert "local_dns" not in webui_env["config_path"].read_text()


def test_a_bad_local_name_is_refused_and_nothing_saved(logged_in_client, webui_env, dhcp_config_dict):
    _serving_lan(webui_env, dhcp_config_dict)
    before = webui_env["config_path"].read_text()
    for data in ({"kind": "hosts", "name": "nas.lan", "address": "10.0.0.300"},
                 {"kind": "hosts", "name": "nas.lan\nserver=6.6.6.6", "address": "10.0.0.5"},
                 {"kind": "zones", "name": "nas.lan", "address": "10.0.0.5"}):
        response = logged_in_client.post("/adblock/local-dns/add", data=data)
        assert "error" in response.headers["location"]
    assert webui_env["config_path"].read_text() == before


def test_local_names_need_the_resolver_serving_the_lan(logged_in_client, webui_env):
    _seed_interface(logged_in_client)
    response = logged_in_client.post("/adblock/local-dns/add",
                                     data={"kind": "hosts", "name": "nas.lan", "address": "10.0.0.20"})
    assert "error" in response.headers["location"]
    assert "serve_lan" in response.headers["location"]
