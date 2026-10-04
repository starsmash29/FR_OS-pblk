"""A1 (review triage): the root helpers authorise each connection by the
peer uid the kernel reports, and the network-parsing daemons no longer
share the webUI's identity.

Before, both sockets were 0660 root:fr_os-webui and every daemon that
parses LAN traffic ran as fr_os-webui, so a bug in any parser could send
`save_config`/`apply` to the apply-helper or `apply` to the update-helper
-- root. These tests talk to real helper servers over real Unix sockets,
so SO_PEERCRED is the kernel's, not a stub's.
"""

from __future__ import annotations

import configparser
import grp
import os
import pwd
import re
import tempfile
import threading
from pathlib import Path

import pytest

from frfw import accounts, paths
from frfw.helper import client, update_client
from frfw.helper.peer import FULL, SENSOR, SENSOR_COMMANDS, PeerPolicy
from frfw.helper.server import ApplyHelperServer
from frfw.helper.update_server import UpdateHelperServer

REPO_ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = REPO_ROOT / "systemd"
SENSOR_UNITS = ("fr-ai-ids.service", "fr-appid.service", "fr-iot-scan.service")
EXAMPLE_CONFIG = REPO_ROOT / "examples" / "config.yaml"


def _serve(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


@pytest.fixture
def apply_helper(tmp_path, monkeypatch):
    """An apply-helper whose policy the test sets; conntrack is faked so
    the sensor command has something harmless to do."""
    monkeypatch.setattr("frfw.conntrack.read_snapshot", lambda: [])
    config_path = tmp_path / "config.yaml"
    config_path.write_text(EXAMPLE_CONFIG.read_text())
    servers = []

    def start(policy: PeerPolicy | None, socket_path: Path | None = None) -> Path:
        socket_path = socket_path or tmp_path / "apply.sock"
        server = ApplyHelperServer(socket_path, config_path, backup_dir=tmp_path / "backups",
                                   peer_policy=policy)
        servers.append((server, _serve(server)))
        return socket_path

    yield start
    for server, thread in servers:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_the_webui_role_may_do_everything(apply_helper, tmp_path):
    sock = apply_helper(PeerPolicy(full_uids=frozenset({os.geteuid()})))
    assert client.ping(sock)["ok"]
    assert client.save_config(EXAMPLE_CONFIG.read_text(), sock)["ok"]


def test_a_sensor_may_only_send_the_sensor_commands(apply_helper, tmp_path):
    sock = apply_helper(PeerPolicy(sensor_uids=frozenset({os.geteuid()})))
    assert client.ping(sock)["ok"]
    assert client.conntrack_sample(sock)["ok"]

    before = (tmp_path / "config.yaml").read_text()
    refused = client.save_config("version: 1\nzones: {}\ninterfaces: {}\n", sock)
    assert not refused["ok"] and "not allowed" in refused["message"]
    assert (tmp_path / "config.yaml").read_text() == before
    for cmd in ("apply", "rollback", "authorize_ztna", "ban_ip", "refresh_adblock", "iot_scan", "xdp_stats"):
        assert not client.send_command({"cmd": cmd}, sock)["ok"], cmd


def test_the_webui_role_reads_the_xdp_counters(apply_helper, monkeypatch):
    """ROADMAP P4-1: the counters are on bpffs, root's; the helper reads
    them for the webUI (here the filter was never loaded: all zero)."""
    from frfw import xdp

    monkeypatch.setattr(xdp, "PIN_STATS_PATH", Path("/nonexistent/fr_os_xdp/stats"))
    sock = apply_helper(PeerPolicy(full_uids=frozenset({os.geteuid()})))
    response = client.xdp_stats(sock)
    assert response == {"ok": True, "stats": {name: 0 for name in xdp.STAT_NAMES}}


def test_an_unknown_uid_gets_nothing_not_even_ping(apply_helper):
    sock = apply_helper(PeerPolicy())
    response = client.ping(sock)
    assert not response["ok"] and "not allowed" in response["message"]


def test_update_helper_refuses_everyone_but_the_full_role(tmp_path):
    for policy, allowed in ((PeerPolicy(sensor_uids=frozenset({os.geteuid()})), False),
                            (PeerPolicy(), False),
                            (PeerPolicy(full_uids=frozenset({os.geteuid()})), True)):
        sock = tmp_path / f"update-{allowed}-{len(policy.sensor_uids)}.sock"
        server = UpdateHelperServer(sock, state_path=tmp_path / "state.json",
                                    releases_dir=tmp_path / "rel", peer_policy=policy)
        thread = _serve(server)
        try:
            response = update_client.ping(sock)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()
        assert response["ok"] is allowed, (policy, response)


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to connect from a second uid")
def test_default_policy_refuses_a_process_running_as_another_user(apply_helper):
    """The real thing: a forked child drops to `nobody` and connects; the
    helper (default policy: root, its own uid, fr_os-webui) must refuse."""
    nobody = pwd.getpwnam("nobody")
    directory = Path(tempfile.mkdtemp(prefix="fros-peer-"))
    directory.chmod(0o755)
    sock = apply_helper(None, directory / "apply.sock")
    sock.chmod(0o777)  # the filesystem lets it in; only the uid check is left
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:  # child
        try:
            os.close(read_end)
            os.setgroups([])
            os.setgid(nobody.pw_gid)
            os.setuid(nobody.pw_uid)
            response = client.send_command({"cmd": "ping"}, sock)
            os.write(write_end, b"ok" if response["ok"] else response["message"].encode())
        finally:
            os._exit(0)
    os.close(write_end)
    os.waitpid(pid, 0)
    answer = os.read(read_end, 4096).decode()
    os.close(read_end)
    assert answer != "ok"
    assert f"uid {nobody.pw_uid}" in answer
    assert client.ping(sock)["ok"]  # root, the same socket


def test_policy_roles():
    policy = PeerPolicy(full_uids=frozenset({0, 1000}), sensor_uids=frozenset({999}))
    assert policy.role(0) == FULL and policy.role(999) == SENSOR and policy.role(5) is None
    assert policy.allows(999, "quarantine_ip") and not policy.allows(999, "save_config")
    assert not policy.allows(999, None)


def test_sensor_commands_are_exactly_what_the_sensor_daemons_send():
    """Every helper call in a sensor daemon must be allowed for the sensor
    role -- and the role must not allow more than they use."""
    used = set()
    for module in ("ai_ids/daemon.py", "tlsfp/daemon.py", "iot/scanner.py"):
        used |= set(re.findall(r"helper_client\.(\w+)", (REPO_ROOT / "src/frfw" / module).read_text()))
    assert used - {"HelperError"} | {"ping"} == SENSOR_COMMANDS


def _unit(name: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read(SYSTEMD / name)
    return parser


@pytest.mark.parametrize("unit", SENSOR_UNITS)
def test_parser_daemons_run_as_the_sensor_account(unit):
    service = _unit(unit)["Service"]
    assert service["User"] == paths.SENSOR_USER
    assert service["Group"] == paths.SENSOR_USER
    assert "fr_os-webui" in service["SupplementaryGroups"].split()  # config.yaml + the socket
    assert "/etc/fr_os/webui" not in service["ReadWritePaths"]


def test_tls_fingerprinting_drops_to_the_sensor_account():
    from frfw import privdrop

    assert privdrop.RUN_AS_USER == paths.SENSOR_USER
    assert "/etc/fr_os/webui" not in _unit("fr-tls-fp.service")["Service"]["ReadWritePaths"]


@pytest.mark.parametrize("unit", SENSOR_UNITS + ("fr-tls-fp.service", "fr-webui.service", "fr-update-helper.socket"))
def test_units_pull_in_the_accounts(unit):
    section = _unit(unit)["Unit"]
    assert "fr-accounts.service" in section["Wants"].split()
    assert "fr-accounts.service" in section["After"].split()


def test_update_socket_is_the_webui_accounts_alone():
    socket = _unit("fr-update-helper.socket")["Socket"]
    assert (socket["SocketMode"], socket["SocketUser"]) == ("0600", paths.WEBUI_USER)


def test_sensor_output_is_not_next_to_the_webui_secrets():
    for path in (paths.AI_IDS_STATE_PATH, paths.IOT_INVENTORY_PATH, paths.APPID_USAGE_PATH, paths.TLSFP_STATE_PATH):
        assert path.parent == paths.SENSOR_STATE_DIR
    assert paths.WEBUI_SECRET_KEY_PATH.parent != paths.SENSOR_STATE_DIR


def test_ensure_accounts_creates_users_and_private_state_dirs(tmp_path, monkeypatch):
    me = pwd.getpwuid(os.geteuid()).pw_name
    my_group = grp.getgrgid(os.getegid()).gr_name
    existing: set[str] = set()
    members: list[str] = []
    ran: list[list[str]] = []

    def fake_run(cmd):
        ran.append(cmd)
        if cmd[0] == "useradd":
            existing.add(cmd[-1])
        if cmd[0] == "usermod":
            members.append(cmd[-1])

    monkeypatch.setattr(accounts, "_run", fake_run)
    monkeypatch.setattr(accounts, "_user_exists", lambda name: name in existing)
    monkeypatch.setattr(accounts, "_group_members", lambda name: members)
    # Directories are owned by real accounts; map ours onto the running user.
    me_entry, my_group_entry = pwd.getpwnam(me), grp.getgrnam(my_group)
    monkeypatch.setattr(accounts.pwd, "getpwnam", lambda name: me_entry)
    monkeypatch.setattr(accounts.grp, "getgrnam", lambda name: my_group_entry)
    monkeypatch.setattr(paths, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(paths, "WEBUI_STATE_DIR", tmp_path / "webui")
    monkeypatch.setattr(paths, "SENSOR_STATE_DIR", tmp_path / "sensors")
    (tmp_path / "webui").mkdir(mode=0o750)  # an older install's mode

    done = accounts.ensure()
    assert existing == {paths.WEBUI_USER, paths.SENSOR_USER}
    assert members == [paths.SENSOR_USER]
    assert len(done) == 3
    assert (tmp_path / "webui").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "sensors").stat().st_mode & 0o777 == 0o750

    ran.clear()
    assert accounts.ensure() == []  # idempotent
    assert ran == []
