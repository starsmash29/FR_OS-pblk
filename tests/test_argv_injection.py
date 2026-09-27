"""Security-lessons F1: no argument injection.

MikroTik's login program took the username `-2` as an option. FR_OS
passes interface names, addresses, unit names, versions, disk paths and
host names to nft, ip, systemctl, pip, sfdisk, openssl... These tests
throw hostile values at every validator, at the config loader, and at
the call sites themselves (with subprocess recorded, never run): nothing
hostile may reach a command line, and values follow `--` wherever the
tool supports it.
"""

from __future__ import annotations

import subprocess

import pytest
import yaml

from frfw import (
    admin_account,
    bruteforce,
    ids_quarantine,
    ifaddr,
    iot_isolation,
    persistence,
    svc,
    update,
    validate,
    xdp,
)
from frfw.config import ConfigError, parse_config
from frfw.config.schema import Interface
from frfw.skeleton import build_skeleton_config

#: Values that start with "-", or contain spaces, newlines, ";", quotes,
#: nft/shell metacharacters, NULs, path tricks -- and over-long ones.
HOSTILE = [
    "-2", "--help", "-o/tmp/x", "-", "--", "eth0 eth1", " eth0", "eth0\n", "eth0\nflush ruleset",
    "eth0;reboot", "eth0'", 'eth0"', "eth0}", "{eth0", "$(id)", "`id`", "../etc", "..", ".",
    "eth0\x00", "\n", "", " ", "x" * 300,
]


@pytest.mark.parametrize("check", [
    validate.ifname, validate.ipv4, validate.ipv4_interface, validate.mac, validate.systemd_unit,
    validate.systemctl_action, validate.version, validate.github_repo, validate.block_device,
    validate.hostname,
])
@pytest.mark.parametrize("value", HOSTILE)
def test_every_validator_refuses_hostile_values(check, value):
    with pytest.raises(validate.ArgumentError):
        check(value)


@pytest.mark.parametrize("check, good", [
    (validate.ifname, "enp2s0.30"), (validate.ipv4, "192.168.1.1"),
    (validate.ipv4_interface, "192.168.1.1/24"), (validate.mac, "AA:bb:cc:dd:ee:ff"),
    (validate.systemd_unit, "kea-dhcp4-server"), (validate.systemctl_action, "try-restart"),
    (validate.version, "v0.2.0"), (validate.github_repo, "starsmash29/FR_OS-pblk"),
    (validate.block_device, "/dev/nvme0n1"), (validate.hostname, "fr-router.lan"),
])
def test_validators_accept_real_values(check, good):
    check(good)


@pytest.mark.parametrize("value", ["aa:bb:cc:dd:ee:ff\n", "admin\n", "0.1.0\n"])
def test_a_trailing_newline_is_never_accepted(value):
    """`^...$` with re.match accepts a trailing newline in Python; these
    used to pass the MAC, username and version checks."""
    with pytest.raises((iot_isolation.IotIsolationError, admin_account.AccountError, update.UpdateError)):
        if ":" in value:
            iot_isolation.normalize_macs([value])
        elif value.startswith("admin"):
            admin_account.validate_username(value)
        else:
            update.parse_version(value)


# -- the config loader ----------------------------------------------------------------


def _raw():
    return yaml.safe_load(build_skeleton_config("eth0", "eth1"))


@pytest.mark.parametrize("value", HOSTILE)
def test_config_refuses_hostile_interface_devices(value):
    raw = _raw()
    raw["interfaces"]["lan"]["device"] = value
    with pytest.raises(ConfigError):
        parse_config(raw)


@pytest.mark.parametrize("value", HOSTILE)
def test_config_refuses_hostile_hostnames(value):
    raw = _raw()
    raw["hostname"] = value
    with pytest.raises(ConfigError):
        parse_config(raw)


@pytest.mark.parametrize("value", HOSTILE + ["owner/../evil", "-o/x", "a/b c"])
def test_config_refuses_hostile_update_repos(value):
    if value == "":
        pytest.skip("empty = the built-in default repo")
    raw = _raw()
    raw["update"] = {"repo": value}
    with pytest.raises(ConfigError):
        parse_config(raw)


@pytest.mark.parametrize("value", ["aa:bb:cc:dd:ee:ff\n", "aa:bb:cc:dd:ee:ff;", "-aa:bb:cc:dd:ee:f"])
def test_config_refuses_hostile_macs(value):
    raw = _raw()
    raw["iot"] = {"enabled": False, "trusted_macs": [value]}
    with pytest.raises(ConfigError):
        parse_config(raw)


# -- the call sites, with subprocess recorded ----------------------------------------------


@pytest.fixture
def argv(monkeypatch):
    """Record every command instead of running it."""
    calls: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(list(cmd))
        if "-keyout" in cmd:  # openssl req: leave the files it would write
            for flag in ("-keyout", "-out"):
                open(cmd[cmd.index(flag) + 1], "w").close()
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("os.geteuid", lambda: 0)
    return calls


@pytest.mark.parametrize("value", HOSTILE)
def test_ifaddr_never_passes_a_hostile_device(argv, value):
    iface = Interface(name="lan", device=value, zone="lan", address="192.168.1.1/24")
    with pytest.raises(ifaddr.IfaddrError):
        ifaddr._apply_one(iface)
    assert argv == []


def test_ifaddr_puts_the_device_after_dev(argv):
    ifaddr._apply_one(Interface(name="lan", device="eth1", zone="lan", address="192.168.1.1/24"))
    for cmd in argv:
        assert cmd[cmd.index("eth1") - 1] == "dev"


@pytest.mark.parametrize("value", HOSTILE)
def test_xdp_never_passes_a_hostile_device(argv, value):
    with pytest.raises(xdp.XdpError):
        xdp.attach(value)
    with pytest.raises(xdp.XdpError):
        xdp.detach(value, xdp.AttachMode.GENERIC)
    with pytest.raises(xdp.XdpError):
        xdp.live_attachment(value)
    assert argv == []


@pytest.mark.parametrize("value", HOSTILE)
def test_systemctl_refuses_hostile_units_and_actions(argv, value, monkeypatch):
    monkeypatch.setattr(svc, "system_is_booting", lambda: False)
    with pytest.raises(validate.ArgumentError):
        svc.systemctl("restart", value)
    with pytest.raises(validate.ArgumentError):
        svc.systemctl(value, "ssh")
    assert argv == []


def test_systemctl_puts_the_unit_after_double_dash(argv, monkeypatch):
    monkeypatch.setattr(svc, "system_is_booting", lambda: False)
    svc.systemctl("reload", "ssh")
    assert argv[-1] == ["systemctl", "reload", "--", "ssh"]


@pytest.mark.parametrize("value", HOSTILE + ["1.2.3.4 }", "1.2.3.4\n", "1.2.3.4;"])
def test_nft_set_elements_refuse_hostile_ips(argv, value):
    with pytest.raises(bruteforce.BruteforceError):
        bruteforce.ban_ip(value, 60)
    with pytest.raises(ids_quarantine.IdsQuarantineError):
        ids_quarantine.quarantine_ip(value, 60)
    assert argv == []


def test_nft_gets_double_dash_before_the_command(argv):
    bruteforce.ban_ip("203.0.113.9", 60)
    assert argv[-1][:2] == ["nft", "--"]
    assert validate.nft_argv(["-j", "list", "ruleset"]) == ["nft", "-j", "--", "list", "ruleset"]
    assert validate.nft_argv(["-c", "-f", "-"]) == ["nft", "-c", "-f", "-"]


@pytest.mark.parametrize("value", HOSTILE + ["aa:bb:cc:dd:ee:ff\nflush ruleset"])
def test_iot_isolation_refuses_hostile_macs(argv, value):
    with pytest.raises(iot_isolation.IotIsolationError):
        iot_isolation.sync_isolated([value])
    assert argv == []


@pytest.mark.parametrize("value", HOSTILE + ["/dev/sda;reboot", "/dev/../etc/shadow", "/tmp/disk"])
def test_persistence_refuses_hostile_disks(argv, value):
    with pytest.raises(persistence.PersistenceError):
        persistence.create_on_disk(value, wipe=True)
    with pytest.raises(persistence.PersistenceError):
        persistence.create_on_boot_medium(value, check_device=False)
    assert argv == []


@pytest.mark.parametrize("value", HOSTILE + ["../../etc", "0.1.0/../../x"])
def test_rollback_refuses_a_tampered_previous_version(tmp_path, argv, value, monkeypatch):
    """The state file names a directory that is rmtree'd and pip-installed
    as root (review triage C2)."""
    state = tmp_path / "state.json"
    update.save_state(update.UpdateState(current_version="0.2.0", previous_version=value or "x"), state)
    monkeypatch.setattr(update, "_installed_version", lambda: "0.2.0")
    fetched = []
    monkeypatch.setattr(update, "_fetch_release", lambda *a: fetched.append(a))
    with pytest.raises(update.UpdateError):
        update.rollback_update(state_path=state, releases_dir=tmp_path / "releases")
    assert fetched == [] and argv == []


@pytest.mark.parametrize("value", ["owner/../evil", "-o/x", "a/b c", "a/b\n", "a b/c"])
def test_the_updater_refuses_a_hostile_repo(value):
    with pytest.raises(update.UpdateError):
        update.check_latest("0.1.0", repo=value)


def test_pip_gets_double_dash_before_the_release(argv, tmp_path, monkeypatch):
    monkeypatch.setattr(update, "_stage_systemd_units", lambda d: None)
    update._install_release_dir(tmp_path / "frfw-0.2.0")
    pip = next(cmd for cmd in argv if cmd[0] == "pip3")
    assert pip[-2] == "--" and pip[-1].endswith("frfw-0.2.0[webui]")


@pytest.mark.parametrize("value", ["fr-router,IP:6.6.6.6", "-newkey", "a/CN=evil", "x\nY"])
def test_the_certificate_request_takes_only_real_names(tmp_path, argv, value):
    from frfw.webui import tls

    with pytest.raises(validate.ArgumentError):
        tls.ensure_self_signed_cert(tmp_path / "c.pem", tmp_path / "k.pem", common_name=value)
    tls.ensure_self_signed_cert(tmp_path / "c.pem", tmp_path / "k.pem", dns_names=[value], ip_addresses=[value])
    request = next(cmd for cmd in argv if cmd[:2] == ["openssl", "req"])
    names = request[request.index("-subj") + 1] + request[request.index("-addext") + 1]
    assert value not in names
    assert request.count(value) == 0 or value == "-newkey" and request.count(value) == 1  # openssl's own flag
