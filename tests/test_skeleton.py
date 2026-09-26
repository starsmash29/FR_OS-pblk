import yaml

from frfw.config import parse_config
from frfw.skeleton import build_skeleton_config


def test_skeleton_with_opt_zone_is_valid_and_complete():
    text = build_skeleton_config("eth0", "eth1", {"dmz": "eth2"}, hostname="myrouter")
    config = parse_config(yaml.safe_load(text))

    assert config.hostname == "myrouter"
    assert config.interfaces["wan"].device == "eth0"
    assert config.interfaces["wan"].zone == "wan"
    assert config.interfaces["lan"].device == "eth1"
    assert config.interfaces["dmz"].device == "eth2"
    assert config.interfaces["dmz"].zone == "dmz"
    assert {r.name for r in config.rules} == {"allow-mgmt-from-lan", "webui-from-lan", "lan-to-wan"}
    assert config.nat.masquerade[0].out_zone == "wan"


def test_skeleton_without_opt_zones():
    text = build_skeleton_config("eth0", "eth1")
    config = parse_config(yaml.safe_load(text))
    assert set(config.interfaces) == {"wan", "lan"}
    assert set(config.zones) == {"wan", "lan"}


def test_skeleton_default_rules_do_not_expose_anything_from_wan():
    text = build_skeleton_config("eth0", "eth1")
    config = parse_config(yaml.safe_load(text))
    assert all(rule.from_zone != "wan" for rule in config.rules)


def test_skeleton_lan_is_usable_out_of_the_box():
    # A fresh router: LAN at 192.168.1.1 with DHCP, and the webUI reachable
    # from the LAN (the input chain's policy is drop).
    config = parse_config(yaml.safe_load(build_skeleton_config("eth0", "eth1")))
    assert config.interfaces["lan"].address == "192.168.1.1/24"
    assert config.interfaces["wan"].address is None  # DHCP from upstream
    pool = config.dhcp.zones["lan"]
    assert (pool.range_start, pool.range_end) == ("192.168.1.100", "192.168.1.199")
    webui = next(r for r in config.rules if r.name == "webui-from-lan")
    assert (webui.from_zone, webui.to_zone, str(webui.dst_port)) == ("lan", "self", "443")
    assert "tcp" in str(webui.proto).lower()


def test_skeleton_without_lan_address():
    config = parse_config(yaml.safe_load(build_skeleton_config("eth0", "eth1", lan_address=None)))
    assert config.interfaces["lan"].address is None
    assert not config.dhcp.zones
