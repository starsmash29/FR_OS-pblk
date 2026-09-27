"""A5 (review triage): the generated admin password is no longer left in
the world-readable /etc/issue forever.

It now lives in a root-only /etc/issue.d file (agetty, running as root,
still shows it on the console) and is removed once the password has been
changed.
"""

from __future__ import annotations

import configparser
import stat
from pathlib import Path

import pytest

from frfw import cli, initial_password
from frfw.admin_account import ROLE_ADMIN, AdminStore

REPO_ROOT = Path(__file__).resolve().parents[1]

V010_ISSUE = (
    "FR_OS: initial webUI admin login is 'admin' / 's3cret-from-first-boot'\n"
    "webUI: https://192.168.1.1/ from a computer on the LAN port (ens4)\n"
    "Change it after logging in, then this line stays until you edit /etc/issue.\n"
    "\n"
    "Debian GNU/Linux 12 \\n \\l\n"
    "\n"
)


@pytest.fixture
def store(tmp_path):
    return AdminStore(tmp_path / "auth.json")


def test_written_root_only_and_readable_back(tmp_path):
    path = tmp_path / "issue.d" / "fr_os-initial-admin.issue"
    initial_password.write("admin", "pw-123456", path=path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert initial_password.read(path) == ("admin", "pw-123456")


def test_kept_while_the_password_still_works(tmp_path, store):
    store.set_password("admin", "pw-123456", ROLE_ADMIN)
    path = tmp_path / "fr_os-initial-admin.issue"
    initial_password.write("admin", "pw-123456", path=path)
    assert initial_password.clear_if_changed(store, path=path) is False
    assert path.exists()


def test_removed_once_the_password_was_changed(tmp_path, store):
    store.set_password("admin", "pw-123456", ROLE_ADMIN)
    path = tmp_path / "fr_os-initial-admin.issue"
    initial_password.write("admin", "pw-123456", path=path)
    store.set_password("admin", "something-new-1", ROLE_ADMIN)
    assert initial_password.clear_if_changed(store, path=path) is True
    assert not path.exists()


def test_a_v010_password_is_moved_out_of_etc_issue(tmp_path, store):
    legacy = tmp_path / "issue"
    legacy.write_text(V010_ISSUE)
    legacy.chmod(0o644)
    path = tmp_path / "issue.d" / "fr_os-initial-admin.issue"
    assert initial_password.migrate_legacy(legacy_path=legacy, path=path) is True
    assert "s3cret-from-first-boot" not in legacy.read_text()
    assert legacy.read_text() == "Debian GNU/Linux 12 \\n \\l\n\n"
    assert stat.S_IMODE(legacy.stat().st_mode) == 0o644
    assert initial_password.read(path) == ("admin", "s3cret-from-first-boot")
    assert initial_password.migrate_legacy(legacy_path=legacy, path=path) is False  # idempotent


def test_cli_show_on_console_never_prints_the_password(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("frfw.admin_account.AUTH_FILE_PATH", tmp_path / "auth.json")
    monkeypatch.setattr(cli, "AdminStore", lambda: AdminStore(tmp_path / "auth.json"))
    issue = tmp_path / "issue.d" / "fr_os-initial-admin.issue"
    monkeypatch.setattr(initial_password, "ISSUE_PATH", issue)
    assert cli.main(["set-admin-password", "--generate", "--show-on-console"]) == 0
    username, password = initial_password.read(issue)
    assert username == "admin" and password not in capsys.readouterr().out
    assert AdminStore(tmp_path / "auth.json").verify("admin", password) is not None


def test_first_boot_keeps_the_password_out_of_etc_issue():
    script = (REPO_ROOT / "scripts" / "fr-first-boot.sh").read_text()
    assert "--show-on-console" in script
    assert "PASSWORD" not in script  # never held in the shell, never echoed into /etc/issue


def test_webui_pulls_in_the_cleanup():
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.read(REPO_ROOT / "systemd" / "fr-webui.service")
    wants = parser["Unit"]["Wants"].split()
    assert {"fr-initial-password.path", "fr-initial-password.service"} <= set(wants)
    path_unit = (REPO_ROOT / "systemd" / "fr-initial-password.path").read_text()
    assert "PathChanged=/etc/fr_os/webui/auth.json" in path_unit


def test_checking_never_writes_the_account_file(tmp_path, store):
    """fr-initial-password's sandbox can't write the webUI's account file
    (security-lessons I1), so the check must not upgrade an old hash in
    place the way a sign-in does."""
    import hashlib
    import json
    import os

    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", b"pw-123456", salt, 200_000)
    store.path.write_text(json.dumps({"version": 2, "users": {"admin": {
        "password_hash": f"pbkdf2_sha256$200000${salt.hex()}${digest.hex()}", "role": ROLE_ADMIN}}}))
    before = store.path.read_text()
    path = tmp_path / "fr_os-initial-admin.issue"
    initial_password.write("admin", "pw-123456", path=path)
    store.path.parent.chmod(0o555)  # as read-only as in the unit
    try:
        assert initial_password.clear_if_changed(store, path=path) is False
    finally:
        store.path.parent.chmod(0o755)
    assert store.path.read_text() == before
