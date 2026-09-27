"""Security-lessons G2: strong password hashing with automatic upgrade.
FortiGates kept legacy hashes until an admin re-typed the password, and
kept the old hash in a hidden field. FR_OS hashes with scrypt (hashlib),
accepts a pre-G2 PBKDF2 hash only at its floor, replaces it on the next
successful sign-in, and keeps nothing of the old one.
"""

from __future__ import annotations

import hashlib
import json
import os

import yaml
from fastapi.testclient import TestClient

from frfw import admin_account
from frfw.admin_account import ROLE_VIEWER, hash_password, needs_rehash, verify_password


def legacy_pbkdf2(password: str, iterations: int = 200_000) -> str:
    """A hash exactly as FR_OS wrote them before G2."""
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def test_new_hashes_are_scrypt_with_the_documented_parameters():
    stored = hash_password("correct-horse-1")
    algorithm, n, r, p, salt, digest = stored.split("$")
    assert (algorithm, int(n), int(r), int(p)) == ("scrypt", 2**15, 8, 3)
    assert len(bytes.fromhex(salt)) == 16 and len(bytes.fromhex(digest)) == 32
    assert verify_password("correct-horse-1", stored)
    assert not verify_password("correct-horse-2", stored)
    assert not needs_rehash(stored)


def test_weaker_scrypt_parameters_never_verify():
    salt = os.urandom(16)
    for n, r, p in ((2**10, 8, 1), (2**14, 8, 1), (2**15, 4, 3), (2**15, 8, 1)):
        digest = hashlib.scrypt(b"pw-123456", salt=salt, n=n, r=r, p=p, maxmem=2**28, dklen=32).hex()
        assert not verify_password("pw-123456", f"scrypt${n}${r}${p}${salt.hex()}${digest}"), (n, r, p)
    # N must be a power of two; a stored hash claiming otherwise fails closed.
    assert not verify_password("pw-123456", f"scrypt${3 * 2**14}$8$3${salt.hex()}${'00' * 32}")


def test_a_legacy_hash_verifies_and_is_marked_for_upgrade():
    stored = legacy_pbkdf2("correct-horse-1")
    assert verify_password("correct-horse-1", stored)
    assert needs_rehash(stored)


def _write_legacy_account(path, username, password, role="admin"):
    path.write_text(json.dumps({"version": 2, "users": {
        username: {"password_hash": legacy_pbkdf2(password), "role": role}}}))


def test_sign_in_replaces_the_legacy_hash_and_keeps_nothing_of_it(webui_env, client):
    auth = webui_env["admin_store"].path
    _write_legacy_account(auth, "netadmin", "correct-horse-1")
    response = client.post("/login", data={"username": "netadmin", "password": "correct-horse-1"})
    assert response.headers["location"] == "/"
    assert client.get("/").status_code == 200  # the session made from the new hash works

    text = auth.read_text()
    assert "pbkdf2" not in text
    entry = json.loads(text)["users"]["netadmin"]
    assert set(entry) == {"password_hash", "role"}  # no old/previous/legacy field
    assert entry["password_hash"].startswith("scrypt$")
    assert webui_env["admin_store"].verify("netadmin", "correct-horse-1") is not None


def test_a_failed_sign_in_does_not_touch_the_legacy_hash(webui_env, client):
    auth = webui_env["admin_store"].path
    _write_legacy_account(auth, "netadmin", "correct-horse-1")
    before = auth.read_text()
    client.post("/login", data={"username": "netadmin", "password": "wrong"})
    assert auth.read_text() == before


def test_the_upgrade_keeps_role_and_setup_flag(tmp_path):
    store = admin_account.AdminStore(tmp_path / "auth.json")
    _write_legacy_account(store.path, "watcher", "viewer-pass-1", ROLE_VIEWER)
    account = store.verify("watcher", "viewer-pass-1")
    assert account.role == ROLE_VIEWER and not needs_rehash(account.password_hash)


def test_ztna_sign_in_upgrades_the_users_hash_in_the_config(app, webui_env):
    webui_env["config_path"].write_text(yaml.safe_dump({
        "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"}, "lan": {"device": "eth1", "zone": "lan"}},
        "rules": [], "nat": {"masquerade": [{"out_zone": "wan"}]},
        "ztna": {"enabled": True, "users": [{"username": "alice", "password_hash": legacy_pbkdf2("alice-pass-1")}]},
    }))
    user = TestClient(app, client=("192.168.1.50", 5555), follow_redirects=False)
    user.post("/ztna/login", data={"username": "alice", "password": "alice-pass-1"})
    assert webui_env["helper"].ztna_status("192.168.1.50")["authorized"] is True
    text = webui_env["config_path"].read_text()
    assert "pbkdf2" not in text
    [alice] = yaml.safe_load(text)["ztna"]["users"]
    assert alice["password_hash"].startswith("scrypt$") and verify_password("alice-pass-1", alice["password_hash"])
