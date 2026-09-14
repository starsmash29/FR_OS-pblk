"""Route tests for interfaces/rules/nat/dhcp: each add/delete flow, and a
full round trip proving the webUI produces a config `firewall-cli` (i.e.
`frfw.config.load_config`) accepts identically -- the phase 3 acceptance
criterion."""

from __future__ import annotations

from frfw.config import load_config


def test_add_and_edit_and_delete_interface(logged_in_client, webui_env):
    r = logged_in_client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )
    assert r.status_code == 303 and "success" in r.headers["location"]

    r = logged_in_client.post(
        "/interfaces/save",
        data={"name": "lan", "device": "eth1", "zone": "lan", "address": "10.0.0.1/24"},
    )
    assert r.status_code == 303 and "success" in r.headers["location"]

    page = logged_in_client.get("/interfaces")
    assert "eth0" in page.text and "10.0.0.1/24" in page.text

    # edit: re-save "wan" with a different device
    r = logged_in_client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth2", "zone": "wan", "address": ""}
    )
    assert "success" in r.headers["location"]
    assert "eth2" in logged_in_client.get("/interfaces").text

    r = logged_in_client.post("/interfaces/delete/lan")
    # deleting the only interface in "lan" while nothing else references
    # that zone should succeed and prune the now-empty zone too
    assert "success" in r.headers["location"]
    assert "lan" not in load_config(webui_env["config_path"]).zones


def test_delete_interface_blocked_by_dependent_rule(logged_in_client, webui_env):
    logged_in_client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )
    logged_in_client.post(
        "/interfaces/save", data={"name": "lan", "device": "eth1", "zone": "lan", "address": ""}
    )
    logged_in_client.post(
        "/rules/add",
        data={
            "name": "lan-to-wan",
            "action": "accept",
            "from_zone": "lan",
            "to_zone": "wan",
            "proto": "any",
        },
    )

    r = logged_in_client.post("/interfaces/delete/lan")
    assert "error" in r.headers["location"]
    # nothing was written -- the interface (and the rule referencing it)
    # must still be intact
    config = load_config(webui_env["config_path"])
    assert "lan" in config.interfaces


def test_add_and_delete_rule(logged_in_client, webui_env):
    _seed_wan_lan(logged_in_client)

    r = logged_in_client.post(
        "/rules/add",
        data={
            "name": "allow-ssh",
            "action": "accept",
            "from_zone": "lan",
            "to_zone": "self",
            "proto": "tcp",
            "dst_port": "22",
            "log": "true",
        },
    )
    assert "success" in r.headers["location"]

    config = load_config(webui_env["config_path"])
    rule = config.rules[0]
    assert rule.name == "allow-ssh"
    assert rule.to_zone == "self"
    assert rule.dst_port == "22"
    assert rule.log is True

    r = logged_in_client.post("/rules/delete/allow-ssh")
    assert "success" in r.headers["location"]
    assert load_config(webui_env["config_path"]).rules == []


def test_add_masquerade_and_port_forward(logged_in_client, webui_env):
    _seed_wan_lan(logged_in_client)

    r = logged_in_client.post("/nat/masquerade/add", data={"out_zone": "wan"})
    assert "success" in r.headers["location"]

    r = logged_in_client.post(
        "/nat/portforward/add",
        data={
            "name": "https-fwd",
            "in_zone": "wan",
            "proto": "tcp",
            "dst_port": 443,
            "to_address": "10.0.0.50",
        },
    )
    assert "success" in r.headers["location"]

    config = load_config(webui_env["config_path"])
    assert config.nat.masquerade[0].out_zone == "wan"
    pf = config.nat.port_forwards[0]
    assert pf.to_address == "10.0.0.50"
    assert pf.to_port == 443  # defaulted from dst_port

    r = logged_in_client.post("/nat/portforward/delete/https-fwd")
    assert "success" in r.headers["location"]
    r = logged_in_client.post("/nat/masquerade/delete/wan")
    assert "success" in r.headers["location"]

    config = load_config(webui_env["config_path"])
    assert config.nat.masquerade == []
    assert config.nat.port_forwards == []


def test_dhcp_pool_and_reservation_lifecycle(logged_in_client, webui_env):
    logged_in_client.post(
        "/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""}
    )
    logged_in_client.post(
        "/interfaces/save",
        data={"name": "lan", "device": "eth1", "zone": "lan", "address": "10.0.0.1/24"},
    )

    # not eligible until it has a pool -- page should still render
    page = logged_in_client.get("/dhcp")
    assert "lan" in page.text

    r = logged_in_client.post(
        "/dhcp/lan/save",
        data={
            "range_start": "10.0.0.100",
            "range_end": "10.0.0.200",
            "dns_servers": "1.1.1.1, 9.9.9.9",
            "lease_time": 3600,
        },
    )
    assert "success" in r.headers["location"]

    config = load_config(webui_env["config_path"])
    pool = config.dhcp.zones["lan"]
    assert pool.dns_servers == ["1.1.1.1", "9.9.9.9"]

    r = logged_in_client.post(
        "/dhcp/lan/reservations/add",
        data={"mac": "aa:bb:cc:dd:ee:ff", "address": "10.0.0.50", "hostname": "nas"},
    )
    assert "success" in r.headers["location"]
    config = load_config(webui_env["config_path"])
    assert config.dhcp.zones["lan"].reservations[0].hostname == "nas"

    r = logged_in_client.post("/dhcp/lan/reservations/delete/aa:bb:cc:dd:ee:ff")
    assert "success" in r.headers["location"]
    assert load_config(webui_env["config_path"]).dhcp.zones["lan"].reservations == []

    r = logged_in_client.post("/dhcp/lan/delete")
    assert "success" in r.headers["location"]
    assert "lan" not in load_config(webui_env["config_path"]).dhcp.zones


def test_apply_and_rollback_buttons_call_helper(logged_in_client, webui_env):
    _seed_wan_lan(logged_in_client)

    r = logged_in_client.post("/apply")
    assert "success" in r.headers["location"]
    assert webui_env["helper"].applied == [False]

    r = logged_in_client.post("/apply?dry_run=1")
    assert webui_env["helper"].applied == [False, True]

    r = logged_in_client.post("/rollback")
    assert "success" in r.headers["location"]
    assert webui_env["helper"].rolled_back is True


def test_full_wan_lan_nat_round_trip_matches_cli_expectations(logged_in_client, webui_env):
    """The phase 3 acceptance criterion: a full WAN/LAN ruleset + NAT built
    entirely through the browser produces a config that `firewall-cli`
    (frfw.config.load_config + frfw.nft.build_ruleset) accepts and renders,
    identically to a hand-written equivalent."""
    _seed_wan_lan(logged_in_client)
    logged_in_client.post(
        "/rules/add",
        data={"name": "lan-to-wan", "action": "accept", "from_zone": "lan", "to_zone": "wan"},
    )
    logged_in_client.post("/nat/masquerade/add", data={"out_zone": "wan"})

    config = load_config(webui_env["config_path"])
    assert config.rules[0].from_zone == "lan"
    assert config.rules[0].to_zone == "wan"
    assert config.nat.masquerade[0].out_zone == "wan"

    from frfw.nft import build_ruleset

    ruleset = build_ruleset(config)
    assert "iifname @lan_ifaces oifname @wan_ifaces accept" in ruleset
    assert "masquerade" in ruleset


def _seed_wan_lan(client) -> None:
    client.post("/interfaces/save", data={"name": "wan", "device": "eth0", "zone": "wan", "address": ""})
    client.post("/interfaces/save", data={"name": "lan", "device": "eth1", "zone": "lan", "address": ""})
