"""Only the admin moves the webUI and SSH (ROADMAP SEC-27).

`management.addresses` is where they listen. Every one must be on the
router, so a change that would take one away is refused when it is
saved; an apply that would move them without a change to the management
settings is refused too (a config from before SEC-27, which has no
addresses); `firewall-cli management-addresses` -- like the webUI's
action -- changes only that, and applies it. The helper's side is in
tests/test_helper.py.
"""

from __future__ import annotations

import pytest
import yaml

from frfw import apply_confirm, management, paths
from frfw.config import ConfigError, parse_config
from frfw.skeleton import build_skeleton_config


def _raw(**management_section) -> dict:
    raw = yaml.safe_load(build_skeleton_config("eth0", "eth1"))
    raw["zones"]["vpn"] = {}
    raw["wireguard"] = {"enabled": True, "address": "10.99.0.1/24"}
    if management_section:
        raw["management"] = management_section
    return raw


def test_a_new_router_listens_where_its_skeleton_says():
    raw = yaml.safe_load(build_skeleton_config("eth0", "eth1"))
    assert raw["management"] == {"addresses": ["10.73.1.1"]}
    assert management.listen_addresses(parse_config(raw)) == ["127.0.0.1", "10.73.1.1"]


@pytest.mark.parametrize("change, why", [
    (lambda r: r["interfaces"]["lan"].update(address="10.73.1.3/24"), "the LAN's address changed"),
    (lambda r: r["interfaces"]["lan"].pop("address"), "the LAN's address removed"),
    (lambda r: r["management"].update(zones=["vpn"]), "the LAN no longer a management zone"),
    (lambda r: r["wireguard"].update(enabled=False), "the VPN turned off"),
])
def test_a_change_that_takes_a_webui_address_away_is_refused(change, why):
    raw = _raw(addresses=["10.73.1.1", "10.99.0.1"])
    raw["dhcp"].pop("lan")  # a DHCP pool would refuse a moved LAN address on its own
    change(raw)
    with pytest.raises(ConfigError, match=r"where the webUI and SSH listen .* System -> webUI address"):
        parse_config(raw)


@pytest.mark.parametrize("value", [["10.73.1.1/24"], ["not-an-ip"], "10.73.1.1", [1]])
def test_addresses_are_plain_ipv4_addresses(value):
    with pytest.raises(ConfigError, match="management.addresses"):
        parse_config(_raw(addresses=value))


def test_what_the_admin_can_choose():
    config = parse_config(_raw(addresses=["10.73.1.1"]))
    assert management.address_choices(config) == [("10.73.1.1", "interface lan"),
                                                   ("10.99.0.1", "the VPN's tunnel")]


def test_an_apply_may_not_move_management_unless_the_management_settings_changed():
    legacy = _raw()
    del legacy["management"]
    before = parse_config(legacy)
    moved = dict(legacy, interfaces={**legacy["interfaces"],
                                     "lan": {**legacy["interfaces"]["lan"], "address": "10.73.1.3/24"}})
    moved.pop("dhcp")
    why = management.moves_management(parse_config(moved), before)
    assert why and "from 127.0.0.1, 10.73.1.1 to 127.0.0.1, 10.73.1.3" in why
    assert management.moves_management(parse_config(dict(moved, management={"addresses": ["10.73.1.3"]})),
                                       before) is None, "the admin moved it"
    assert management.moves_management(before, before) is None
    assert management.moves_management(parse_config(moved), None) is None, "nothing applied yet"


# --- firewall-cli ----------------------------------------------------------------


@pytest.fixture
def router(tmp_path, monkeypatch):
    """config.yaml applied (recorded); apply_all stood in."""
    from frfw import cli

    config_path = tmp_path / "config.yaml"
    text = yaml.safe_dump(_raw(addresses=["10.73.1.1"]), sort_keys=False)
    config_path.write_text(text)
    paths.APPLIED_CONFIG_PATH.write_text(text)
    applied = []

    def apply_all(config, **kwargs):
        applied.append(list(config.management.addresses))
        return type("Result", (), {"messages": []})()

    monkeypatch.setattr(cli, "apply_all", apply_all)
    return cli, config_path, applied


def test_the_console_moves_management_and_applies_only_that(router):
    cli, config_path, applied = router
    assert cli.main(["management-addresses", "10.73.1.1", "10.99.0.1", "--config", str(config_path)]) == 0
    assert yaml.safe_load(config_path.read_text())["management"]["addresses"] == ["10.73.1.1", "10.99.0.1"]
    assert applied == [["10.73.1.1", "10.99.0.1"]]


def test_the_console_won_t_move_management_over_unapplied_changes(router, capsys):
    cli, config_path, applied = router
    raw = yaml.safe_load(config_path.read_text())
    raw["hostname"] = "edited"
    config_path.write_text(yaml.safe_dump(raw))
    before = config_path.read_text()
    assert cli.main(["management-addresses", "10.99.0.1", "--config", str(config_path)]) == 1
    assert "changes that aren't applied" in capsys.readouterr().err
    assert config_path.read_text() == before and applied == []


def test_an_address_that_isn_t_on_the_router_is_refused(router, capsys):
    cli, config_path, applied = router
    before = config_path.read_text()
    assert cli.main(["management-addresses", "192.168.77.1", "--config", str(config_path)]) == 1
    assert config_path.read_text() == before and applied == []


def test_the_console_s_apply_may_not_move_management_either(router, capsys):
    cli, config_path, applied = router
    legacy = _raw()
    del legacy["management"]
    paths.APPLIED_CONFIG_PATH.write_text(yaml.safe_dump(legacy))
    legacy["interfaces"]["lan"]["address"] = "10.73.1.3/24"
    legacy.pop("dhcp")
    config_path.write_text(yaml.safe_dump(legacy))
    assert cli.main(["apply", str(config_path)]) == 1
    assert "would move the webUI and SSH" in capsys.readouterr().err and applied == []
    assert apply_confirm.read() is None
