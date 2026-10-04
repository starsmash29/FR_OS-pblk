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
    # ROADMAP SEC-11: the shared group (the socket, the event feeds) and
    # nothing of the webUI's -- that group reads config.yaml's secrets.
    assert service["SupplementaryGroups"].split() == [paths.FEEDS_GROUP]
    assert "/etc/fr_os/webui" not in service["ReadWritePaths"]
    assert "fr-firewall.service" in _unit(unit)["Unit"]["After"].split()  # it writes their config copy


def test_the_apply_helper_socket_is_the_shared_group_s():
    socket = _unit("fr-apply-helper.socket")["Socket"]
    assert (socket["SocketMode"], socket["SocketUser"], socket["SocketGroup"]) == ("0660", "root", paths.FEEDS_GROUP)
    assert _unit("fr-webui.service")["Service"]["SupplementaryGroups"].split() == [paths.FEEDS_GROUP]


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


class _FakeAccounts:
    """/etc/passwd and /etc/group as frfw.accounts sees them, changed only
    through the commands it runs."""

    def __init__(self, members: dict[str, list[str]] | None = None, users: set[str] | None = None):
        self.users: set[str] = set(users or ())
        self.members: dict[str, list[str]] = {k: list(v) for k, v in (members or {}).items()}
        self.ran: list[list[str]] = []

    def run(self, cmd):
        self.ran.append(cmd)
        if cmd[0] == "useradd":
            self.users.add(cmd[-1])
            self.members.setdefault(cmd[-1], [])
        elif cmd[0] == "groupadd":
            self.members.setdefault(cmd[-1], [])
        elif cmd[0] == "usermod":  # usermod --append --groups GROUP -- USER
            self.members.setdefault(cmd[3], []).append(cmd[-1])
        elif cmd[0] == "gpasswd":  # gpasswd --delete USER GROUP
            self.members[cmd[3]].remove(cmd[2])


@pytest.fixture
def fake_accounts(tmp_path, monkeypatch):
    me = pwd.getpwuid(os.geteuid()).pw_name
    my_group = grp.getgrgid(os.getegid()).gr_name

    def install(fake: _FakeAccounts) -> _FakeAccounts:
        monkeypatch.setattr(accounts, "_run", fake.run)
        monkeypatch.setattr(accounts, "_user_exists", lambda name: name in fake.users)
        monkeypatch.setattr(accounts, "_group_exists", lambda name: name in fake.members)
        monkeypatch.setattr(accounts, "_group_members", lambda name: list(fake.members.get(name, [])))
        return fake

    # Directories are owned by real accounts; map ours onto the running user.
    me_entry, my_group_entry = pwd.getpwnam(me), grp.getgrnam(my_group)
    monkeypatch.setattr(accounts.pwd, "getpwnam", lambda name: me_entry)
    monkeypatch.setattr(accounts.grp, "getgrnam", lambda name: my_group_entry)
    monkeypatch.setattr(paths, "CONFIG_PATH", tmp_path / "config.yaml")
    monkeypatch.setattr(paths, "WEBUI_STATE_DIR", tmp_path / "webui")
    monkeypatch.setattr(paths, "SENSOR_STATE_DIR", tmp_path / "sensors")
    monkeypatch.setattr(paths, "AUDIT_LOG_DIR", tmp_path / "audit")
    for name in ("SNI_EVENTS_DIR", "DNS_QUERY_LOG_DIR"):
        monkeypatch.setattr(paths, name, tmp_path / name.lower())
    monkeypatch.setattr(paths, "SNI_EVENTS_PATH", tmp_path / "sni_events_dir" / "events.jsonl")
    monkeypatch.setattr(paths, "DNS_QUERY_LOG_PATH", tmp_path / "dns_query_log_dir" / "queries.log")
    monkeypatch.setattr(paths, "APPLY_SOCKET_PATH", tmp_path / "apply.sock")
    return install


def test_ensure_accounts_creates_users_and_private_state_dirs(tmp_path, fake_accounts):
    fake = fake_accounts(_FakeAccounts(members={paths.SSH_GROUP: []}))
    (tmp_path / "webui").mkdir(mode=0o750)  # an older install's mode

    done = accounts.ensure()
    assert fake.users == {paths.WEBUI_USER, paths.SENSOR_USER}
    # ROADMAP SEC-11: both in the shared group, the sensor in no group of the webUI's.
    assert sorted(fake.members[paths.FEEDS_GROUP]) == sorted([paths.WEBUI_USER, paths.SENSOR_USER])
    assert paths.SENSOR_USER not in fake.members[paths.WEBUI_USER]
    assert len(done) == 5
    assert (tmp_path / "webui").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "sensors").stat().st_mode & 0o777 == 0o750

    fake.ran.clear()
    assert accounts.ensure() == []  # idempotent
    assert fake.ran == []


def test_an_updated_router_moves_the_sensor_out_of_the_webui_group(tmp_path, fake_accounts):
    """ROADMAP SEC-11: a router from before has fr_os-sensor in fr_os-webui
    and its feeds -- and the live socket -- in that group. One ensure()
    (fr-accounts, at boot and on an update) moves all of it."""
    fake = fake_accounts(_FakeAccounts(users={paths.WEBUI_USER, paths.SENSOR_USER},
                                       members={paths.WEBUI_USER: [paths.SENSOR_USER], paths.SENSOR_USER: [],
                                                paths.SSH_GROUP: []}))
    feeds_gid = grp.getgrgid(os.getegid()).gr_gid  # what the fake getgrnam answers for fr_os-feeds
    other_gid = next(g.gr_gid for g in grp.getgrall() if g.gr_gid != feeds_gid)
    old_files = [paths.SNI_EVENTS_DIR, paths.SNI_EVENTS_PATH, paths.DNS_QUERY_LOG_DIR, paths.DNS_QUERY_LOG_PATH,
                 paths.APPLY_SOCKET_PATH]
    for path in old_files:
        if path.suffix:
            path.parent.mkdir(exist_ok=True)
            path.write_text("")
        else:
            path.mkdir(exist_ok=True)
    if os.geteuid() == 0:
        for path in old_files:
            os.chown(path, -1, other_gid)
    done = accounts.ensure()
    assert ["gpasswd", "--delete", paths.SENSOR_USER, paths.WEBUI_USER] in fake.ran
    assert fake.members[paths.WEBUI_USER] == []
    assert sorted(fake.members[paths.FEEDS_GROUP]) == sorted([paths.WEBUI_USER, paths.SENSOR_USER])
    if os.geteuid() == 0:
        assert all(path.stat().st_gid == feeds_gid for path in old_files)
        assert sum(line.startswith("moved ") for line in done) == len(old_files)
