from pathlib import Path

import pytest

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def example_config_path() -> Path:
    return EXAMPLES_DIR / "config.yaml"


@pytest.fixture
def minimal_config_dict() -> dict:
    return {
        "version": 1,
        "hostname": "test-router",
        "interfaces": {
            "wan": {"device": "eth0", "zone": "wan"},
            "lan": {"device": "eth1", "zone": "lan"},
        },
        "zones": {"wan": {}, "lan": {}},
        "rules": [
            {"name": "lan-to-wan", "action": "accept", "from_zone": "lan", "to_zone": "wan"},
        ],
        "nat": {"masquerade": [{"out_zone": "wan"}]},
    }


@pytest.fixture
def dhcp_config_dict(minimal_config_dict) -> dict:
    """`minimal_config_dict`, but the LAN interface has a static address
    (device set to "lo" so real `kea-dhcp4 -t` checks -- which validate
    that listed interfaces actually exist -- pass in any test environment)
    and a DHCP pool for it."""
    minimal_config_dict["interfaces"]["lan"]["device"] = "lo"
    minimal_config_dict["interfaces"]["lan"]["address"] = "10.0.0.1/24"
    minimal_config_dict["dhcp"] = {
        "lan": {
            "range_start": "10.0.0.100",
            "range_end": "10.0.0.200",
            "dns_servers": ["1.1.1.1"],
            "reservations": [
                {"mac": "aa:bb:cc:dd:ee:ff", "address": "10.0.0.50", "hostname": "nas"},
            ],
        }
    }
    return minimal_config_dict


@pytest.fixture(autouse=True)
def _never_touch_the_hosts_sshd(tmp_path, monkeypatch):
    """No test may write /etc/ssh or reload the machine's own sshd: the
    management drop-in goes to tmp_path, and the sshd used to check it is
    one that doesn't exist -- tests of the drop-in pass a real or fake
    sshd explicitly."""
    from frfw import management, paths

    monkeypatch.setattr(paths, "SSHD_MANAGEMENT_DROPIN_PATH", tmp_path / "sshd_config.d" / "40-fr_os-management.conf")
    monkeypatch.setattr(management, "SSHD_BINARY", "fr-os-tests-have-no-sshd")


@pytest.fixture(autouse=True)
def _never_touch_the_hosts_sensor_config(tmp_path_factory, monkeypatch):
    """The parser daemons' secrets-free config copy (ROADMAP SEC-11) is
    written by every save and apply; never the machine's own /etc/fr_os."""
    from frfw import paths

    monkeypatch.setattr(paths, "SENSOR_CONFIG_PATH", tmp_path_factory.mktemp("etc_fr_os") / "sensor-config.yaml")


@pytest.fixture(autouse=True)
def _never_touch_the_hosts_applied_config(tmp_path_factory, monkeypatch):
    """The record of the last applied config (ROADMAP SEC-5,
    /etc/fr_os/applied-config.yaml) is a file of each test's own."""
    from frfw import paths

    monkeypatch.setattr(paths, "APPLIED_CONFIG_PATH", tmp_path_factory.mktemp("etc_fr_os_applied") / "applied-config.yaml")


@pytest.fixture(autouse=True)
def _never_touch_the_hosts_webui_listen_record(tmp_path_factory, monkeypatch):
    """Where an apply records the webUI's listen addresses (ROADMAP SEC-5)."""
    from frfw import paths

    monkeypatch.setattr(paths, "WEBUI_LISTEN_PATH", tmp_path_factory.mktemp("etc_fr_os_listen") / "webui-listen.json")


@pytest.fixture(autouse=True)
def _every_device_a_config_names_exists(monkeypatch):
    """An apply's preflight requires the network devices its steps act on
    (ROADMAP SEC-5); test configs name eth0/eth1, which this machine need
    not have. Tests of the check itself use the real one
    (frfw.ifaddr.NET_CLASS_DIR) or real network namespaces."""
    from frfw import ifaddr

    monkeypatch.setattr(ifaddr, "device_exists", lambda device: True)


@pytest.fixture(autouse=True)
def _never_touch_the_hosts_audit_log(tmp_path_factory, monkeypatch):
    """The root-owned audit log (/var/log/fr_os) is a directory of its own
    per test, never the machine's."""
    from frfw import paths

    log_dir = tmp_path_factory.mktemp("var_log_fr_os")
    monkeypatch.setattr(paths, "AUDIT_LOG_DIR", log_dir)
    monkeypatch.setattr(paths, "AUDIT_LOG_PATH", log_dir / "audit.log")


@pytest.fixture(autouse=True)
def _never_touch_the_hosts_update_check(tmp_path_factory, monkeypatch):
    """The periodic update check's cache (/etc/fr_os/update_check.json)."""
    from frfw import paths

    monkeypatch.setattr(paths, "UPDATE_CHECK_PATH", tmp_path_factory.mktemp("etc_fr_os") / "update_check.json")


@pytest.fixture(autouse=True)
def _never_touch_the_hosts_ip_forwarding(tmp_path_factory, monkeypatch):
    """An apply turns IPv4 forwarding on (frfw.forwarding); in tests that
    switch is a file of its own (not in tmp_path, which some tests list),
    never the machine's /proc/sys."""
    from frfw import forwarding

    switch = tmp_path_factory.mktemp("proc_sys") / "ip_forward"
    switch.write_text("0\n")
    monkeypatch.setattr(forwarding, "IP_FORWARD_PATH", switch)


@pytest.fixture(autouse=True)
def _never_touch_the_hosts_wireguard(tmp_path_factory, monkeypatch):
    """An apply syncs the WireGuard tunnel (frfw.wireguard): in tests there
    is no wg0 and nothing runs `ip`/`wg` on the machine, and the router's
    key goes to a directory of its own. Tests of the real tunnel pass
    their own runner."""
    import subprocess

    from frfw import paths, wireguard

    def no_tunnel_here(argv, *, input=None, check=True):
        return subprocess.CompletedProcess(argv, 1 if argv[:3] == ["ip", "link", "show"] else 0, "", "")

    key_dir = tmp_path_factory.mktemp("etc_fr_os_wireguard")
    monkeypatch.setattr(paths, "WIREGUARD_KEY_PATH", key_dir / "private.key")
    monkeypatch.setattr(wireguard, "_run", no_tunnel_here)


@pytest.fixture(autouse=True)
def _never_touch_the_hosts_xdp_object(tmp_path_factory, monkeypatch):
    """The compiled XDP program an update installs (ROADMAP P4-1,
    /usr/local/share/fr_os/bpf/xdp_sni_filter.o)."""
    from frfw import paths

    monkeypatch.setattr(paths, "XDP_BPF_OBJ_PATH", tmp_path_factory.mktemp("share_fr_os_bpf") / "xdp_sni_filter.o")


@pytest.fixture(autouse=True)
def _never_touch_the_hosts_rule_hits(tmp_path_factory, monkeypatch):
    """The per-rule hit record (security-lessons K2, /etc/fr_os/rule_hits.json)."""
    from frfw import paths

    monkeypatch.setattr(paths, "RULE_HITS_PATH", tmp_path_factory.mktemp("etc_fr_os_hits") / "rule_hits.json")


@pytest.fixture(autouse=True)
def _never_read_the_hosts_runtime_sets(request, monkeypatch):
    """An apply carries the jail, quarantine, ZTNA and IoT sets over the
    reload (frfw.provision, review FR-002) by reading them from the
    kernel first; in tests there is nothing to carry unless a test says
    so with @pytest.mark.reads_runtime_sets."""
    if request.node.get_closest_marker("reads_runtime_sets"):
        return
    from frfw import provision
    from frfw.nft import RuntimeSets

    monkeypatch.setattr(provision, "_read_runtime_sets", lambda config: RuntimeSets())
