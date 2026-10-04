"""The parser daemons read the configuration without its secrets (ROADMAP SEC-11).

Review v0.2.0 R17: fr-ai-ids, fr-appid, fr-iot-scan and fr-tls-fp parse
untrusted network input, and read config.yaml -- ZTNA password hashes and
the metrics token digest in it -- through the webUI's group. They now read
paths.SENSOR_CONFIG_PATH, a copy root writes without those secrets, and are
in no group of the webUI's (tests/test_helper_peer.py,
tests/test_systemd_sandbox.py; the boot test checks the router itself).
"""

from __future__ import annotations

import importlib.util
import os
import stat
import threading
from pathlib import Path

import pytest
import yaml

from frfw import cli, paths, xdp
from frfw.config import parse_config
from frfw.config import export
from frfw.helper import client
from frfw.helper.peer import PeerPolicy
from frfw.helper.server import ApplyHelperServer
from frfw.metrics import generate_metrics_token
from frfw.provision import ProvisionResult

REPO = Path(__file__).resolve().parents[1]
EXAMPLE_CONFIG = REPO / "examples" / "config.yaml"
HASH = "pbkdf2_sha256$600000$c2FsdHNhbHQ=$aGFzaGhhc2hoYXNoaGFzaA=="


def _raw_with_secrets() -> tuple[dict, str]:
    raw = yaml.safe_load(EXAMPLE_CONFIG.read_text())
    raw["ztna"] = {**(raw.get("ztna") or {}), "users": [{"username": "alice", "password_hash": HASH}]}
    _, digest = generate_metrics_token()
    raw["metrics"] = {"site": "budapest", "token_sha256": digest}
    parse_config(raw)
    return raw, digest


def test_the_copy_has_no_secrets_and_is_still_a_valid_config(tmp_path):
    raw, digest = _raw_with_secrets()
    path = export.write_sensor_copy(raw, tmp_path / "sensor-config.yaml")
    text = path.read_text()
    assert HASH not in text and digest not in text
    assert text.startswith(export.SENSOR_COPY_HEADER)
    copy = parse_config(yaml.safe_load(text))  # the daemons load it like config.yaml
    assert copy.metrics.site == "budapest" and copy.metrics.token_sha256 is None
    assert raw["metrics"]["token_sha256"] == digest, "the caller's config was changed"


def test_the_copy_is_root_s_readable_by_the_sensor_group_only(tmp_path):
    path = export.write_sensor_copy({"version": 1}, tmp_path / "sensor-config.yaml")
    st = path.stat()
    assert stat.S_IMODE(st.st_mode) == 0o640
    if os.geteuid() == 0:
        assert st.st_uid == 0
    assert not list(tmp_path.glob("*.tmp")), "a temporary file was left behind"


def test_refreshing_never_fails_the_save_or_apply_it_follows(tmp_path):
    problem = export.refresh_sensor_copy(tmp_path / "missing.yaml", tmp_path / "sensor-config.yaml")
    assert problem and "sensors' config copy" in problem
    assert not (tmp_path / "sensor-config.yaml").exists()


@pytest.fixture
def helper(tmp_path):
    config_path = tmp_path / "config.yaml"
    server = ApplyHelperServer(tmp_path / "apply.sock", config_path, backup_dir=tmp_path / "backups",
                               peer_policy=PeerPolicy(full_uids=frozenset({os.geteuid()})),
                               sensor_config_path=tmp_path / "sensor-config.yaml")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield tmp_path / "apply.sock", config_path, tmp_path / "sensor-config.yaml"
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()


def test_a_save_through_the_helper_refreshes_the_copy(helper):
    """The webUI saves through the helper, and the daemons re-read their
    copy: a change reaches them without an apply, its secrets never."""
    sock, config_path, copy_path = helper
    raw, digest = _raw_with_secrets()
    assert client.save_config(yaml.safe_dump(raw), sock)["ok"]
    assert digest in config_path.read_text()
    text = copy_path.read_text()
    assert digest not in text and HASH not in text and "budapest" in text


def test_firewall_cli_apply_refreshes_the_copy_and_a_dry_run_does_not(tmp_path, monkeypatch):
    """fr-firewall.service runs `firewall-cli apply` at boot: the copy is
    there before the daemons that read it start (they are ordered after it)."""
    raw, digest = _raw_with_secrets()
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(raw))
    monkeypatch.setattr(cli, "apply_all", lambda config, dry_run=False: ProvisionResult(messages=[]))
    assert cli.main(["apply", "--dry-run", str(config_path)]) == 0
    assert not paths.SENSOR_CONFIG_PATH.exists()
    assert cli.main(["apply", str(config_path)]) == 0
    text = paths.SENSOR_CONFIG_PATH.read_text()
    assert digest not in text and HASH not in text


def test_the_daemons_load_the_copy_not_config_yaml(tmp_path, monkeypatch):
    from frfw.appid import daemon as appid_daemon
    from frfw.tlsfp import daemon as tlsfp_daemon

    monkeypatch.setattr(paths, "CONFIG_PATH", tmp_path / "unreadable-config.yaml")
    export.write_sensor_copy(_raw_with_secrets()[0])
    assert appid_daemon._load_config_or_none() is not None
    assert tlsfp_daemon._load_config() is not None


def test_no_parser_daemon_names_config_yaml():
    """A regression guard: whatever a sensor module loads, it is the copy."""
    for package in ("ai_ids", "appid", "tlsfp", "iot"):
        for source in (REPO / "src" / "frfw" / package).glob("*.py"):
            assert "paths.CONFIG_PATH" not in source.read_text(), source


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to give the file another group")
def test_the_sni_event_file_takes_the_logger_s_group_on_every_open(tmp_path):
    """A file an earlier version made with the webUI's group is moved to
    the logger's own (Group=fr_os-feeds) when it opens it, still root."""
    path = tmp_path / "events.jsonl"
    path.write_text("")
    os.chown(path, 0, 4242)
    event_file = xdp.EventFile(path)
    try:
        assert path.stat().st_gid == os.getegid()
        assert stat.S_IMODE(path.stat().st_mode) == 0o640
    finally:
        event_file.close()


def _boot_test():
    spec = importlib.util.spec_from_file_location("qemu_boot_test", REPO / "installer" / "qemu-boot-test.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GROUPS_OK = ("root:x:0:\nfr_os-webui:x:1100:\nfr_os-sensor:x:1101:\n"
             "fr_os-feeds:x:1102:fr_os-webui,fr_os-sensor\n")


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to chown")
@pytest.mark.parametrize("groups, copy_gid, secret_in_copy, ok", [
    (GROUPS_OK, 1101, False, True),
    (GROUPS_OK.replace("fr_os-webui:x:1100:", "fr_os-webui:x:1100:fr_os-sensor"), 1101, False, False),
    (GROUPS_OK.replace("fr_os-webui,fr_os-sensor", "fr_os-webui"), 1101, False, False),
    (GROUPS_OK, 1100, False, False),   # the copy readable by the webUI's group, not the sensors'
    (GROUPS_OK, 1101, True, False),    # the secret got into the copy
])
def test_the_boot_tests_sensor_isolation_check(tmp_path, groups, copy_gid, secret_in_copy, ok):
    upper = tmp_path / "rw"
    (upper / "etc" / "fr_os").mkdir(parents=True)
    (upper / "etc" / "group").write_text(groups)
    config, copy = upper / "etc" / "fr_os" / "config.yaml", upper / "etc" / "fr_os" / "sensor-config.yaml"
    config.write_text("metrics:\n  token_sha256: SECRET\n")
    copy.write_text("metrics:\n  token_sha256: SECRET\n" if secret_in_copy else "metrics: {}\n")
    for path, gid in ((config, 1100), (copy, copy_gid)):
        os.chown(path, 0, gid)
        os.chmod(path, 0o640)
    results = []
    _boot_test().check_sensor_isolation(lambda passed, label: results.append(passed), upper, secret="SECRET")
    assert all(results) is ok
