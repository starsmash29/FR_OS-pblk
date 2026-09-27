"""A6 (review triage): saving the config through the apply-helper keeps
config.yaml's owner and mode.

Before, `_write_atomic` wrote a temp file with the process umask and
renamed it over config.yaml, so the first save from the webUI turned the
root:fr_os-webui 0640 file into root:root 0644 -- world-readable, with
the ZTNA password hashes and the metrics token digest in it.
"""

from __future__ import annotations

import os
import stat
import threading
from pathlib import Path

import pytest

from frfw.helper import client
from frfw.helper.peer import PeerPolicy
from frfw.helper.server import ApplyHelperServer, _write_atomic

EXAMPLE_CONFIG = Path(__file__).resolve().parents[1] / "examples" / "config.yaml"
OTHER_GID = 4242  # stands in for fr_os-webui's group


@pytest.fixture
def helper(tmp_path):
    config_path = tmp_path / "config.yaml"
    server = ApplyHelperServer(tmp_path / "apply.sock", config_path, backup_dir=tmp_path / "backups",
                               peer_policy=PeerPolicy(full_uids=frozenset({os.geteuid()})))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield tmp_path / "apply.sock", config_path
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to give the file another group")
def test_save_config_keeps_group_and_0640(helper):
    sock, config_path = helper
    config_path.write_text(EXAMPLE_CONFIG.read_text())
    os.chown(config_path, 0, OTHER_GID)
    config_path.chmod(0o640)
    old_umask = os.umask(0o022)  # the helper's default umask
    try:
        assert client.save_config(EXAMPLE_CONFIG.read_text() + "\n# saved\n", sock)["ok"]
    finally:
        os.umask(old_umask)
    st = config_path.stat()
    assert stat.S_IMODE(st.st_mode) == 0o640
    assert (st.st_uid, st.st_gid) == (0, OTHER_GID)
    assert config_path.read_text().endswith("# saved\n")


def test_a_new_config_is_not_world_readable(tmp_path):
    path = tmp_path / "config.yaml"
    _write_atomic(path, "version: 1\n")
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_no_temp_file_is_left_behind_and_it_is_never_world_readable(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("old\n")
    path.chmod(0o640)
    seen = []
    real_replace = Path.replace

    def spy(self, target):
        seen.append(stat.S_IMODE(self.stat().st_mode))
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", spy)
    _write_atomic(path, "new\n")
    assert seen == [0o640]
    assert [p.name for p in tmp_path.iterdir()] == ["config.yaml"]
