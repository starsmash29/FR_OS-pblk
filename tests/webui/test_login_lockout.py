"""Security-lessons G6: brute force and credential stuffing.

- the counters survive a webUI restart (they are on disk, 0600);
- an account is locked after 10 failures in 15 minutes from any number
  of addresses -- except from an address that signed in to it before;
- unknown usernames lock the same way (no user enumeration);
- the ZTNA gate is covered as well;
- new passwords are checked against a list of common passwords.
"""

from __future__ import annotations

import stat

import pytest
import yaml
from fastapi.testclient import TestClient

from frfw.admin_account import ROLE_ADMIN, hash_password
from frfw.webui import auth_rate_limiter
from frfw.webui.app import create_app
from frfw.webui.auth_rate_limiter import ACCOUNT_MAX_ATTEMPTS, BruteforceGuard

GOOD = "orchid-lamp-7"


def _from(app, ip: str) -> TestClient:
    return TestClient(app, follow_redirects=False, client=(ip, 50000))


@pytest.fixture
def guarded(webui_env, tmp_path):
    webui_env["bruteforce_guard"] = BruteforceGuard(state_path=tmp_path / "login_guard.json")
    webui_env["admin_store"].set_password("boss", GOOD, ROLE_ADMIN)
    return webui_env


def _stuff(app, username: str, attempts: int = ACCOUNT_MAX_ATTEMPTS) -> None:
    """A credential-stuffing run: one wrong password per address."""
    for i in range(attempts):
        _from(app, f"198.51.100.{i + 1}").post("/login", data={"username": username, "password": f"guess-{i}xx"})


def test_an_account_locks_after_failures_from_many_addresses(guarded):
    app = create_app(**guarded)
    _stuff(app, "boss")
    response = _from(app, "203.0.113.50").post("/login", data={"username": "boss", "password": GOOD})
    assert response.headers["location"].startswith("/login?error=Too+many+failed+sign-ins+for+this+account")
    assert "fr_os_session" not in response.cookies
    # The per-address jail never fired: each address failed once.
    assert guarded["helper"].banned == []


def test_a_known_source_is_not_locked_out(guarded):
    app = create_app(**guarded)
    owner = _from(app, "192.168.1.10")
    assert owner.post("/login", data={"username": "boss", "password": GOOD}).headers["location"] == "/"
    _stuff(app, "boss")
    assert _from(app, "192.168.1.10").post("/login", data={"username": "boss", "password": GOOD}) \
        .headers["location"] == "/"


def test_the_lock_expires(guarded, monkeypatch):
    app = create_app(**guarded)
    clock = {"t": 1_000_000.0}
    monkeypatch.setattr(auth_rate_limiter, "_now", lambda: clock["t"])
    _stuff(app, "boss")
    assert "error" in _from(app, "203.0.113.50").post("/login", data={"username": "boss", "password": GOOD}) \
        .headers["location"]
    clock["t"] += auth_rate_limiter.ACCOUNT_WINDOW_SECONDS + 1
    assert _from(app, "203.0.113.50").post("/login", data={"username": "boss", "password": GOOD}) \
        .headers["location"] == "/"


def test_unknown_usernames_lock_the_same_way(guarded):
    """Otherwise the lock message would tell which usernames exist."""
    app = create_app(**guarded)
    _stuff(app, "nosuchuser")
    response = _from(app, "203.0.113.50").post("/login", data={"username": "nosuchuser", "password": "whatever-1x"})
    assert "Too+many+failed+sign-ins+for+this+account" in response.headers["location"]


def test_the_counters_survive_a_restart(guarded, tmp_path):
    app = create_app(**guarded)
    _stuff(app, "boss")
    state = tmp_path / "login_guard.json"
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    # A new process: a fresh guard reading the same file.
    guarded["bruteforce_guard"] = BruteforceGuard(state_path=state)
    restarted = create_app(**guarded)
    response = _from(restarted, "203.0.113.50").post("/login", data={"username": "boss", "password": GOOD})
    assert "Too+many+failed+sign-ins" in response.headers["location"]


def test_the_per_address_jail_counts_persist_too(tmp_path):
    guard = BruteforceGuard(state_path=tmp_path / "g.json")
    for _ in range(4):
        guard.record_failure("198.51.100.7")
    assert BruteforceGuard(state_path=tmp_path / "g.json").record_failure("198.51.100.7") is True


def test_a_corrupt_state_file_starts_fresh(tmp_path):
    (tmp_path / "g.json").write_text("{not json")
    guard = BruteforceGuard(state_path=tmp_path / "g.json")
    assert guard.record_failure("198.51.100.7") is False


def test_a_sign_in_from_a_new_address_is_marked_in_the_audit_log(guarded):
    app = create_app(**guarded)
    _from(app, "192.168.1.10").post("/login", data={"username": "boss", "password": GOOD})
    _from(app, "192.168.1.10").post("/login", data={"username": "boss", "password": GOOD})
    _from(app, "192.168.1.11").post("/login", data={"username": "boss", "password": GOOD})
    logins = [line for line in guarded["audit_log_path"].read_text().splitlines() if '"login"' in line]
    assert ['new_source' in line for line in logins] == [False, False, True]  # the first has nothing to compare to


def test_the_ztna_gate_locks_per_user_too(guarded):
    guarded["config_path"].write_text(yaml.safe_dump({
        "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"},
                       "lan": {"device": "eth1", "zone": "lan", "address": "192.168.1.1/24"}},
        "rules": [], "nat": {"masquerade": [{"out_zone": "wan"}]},
        "ztna": {"enabled": True, "users": [{"username": "alice", "password_hash": hash_password(GOOD)}]},
    }))
    app = create_app(**guarded)
    for i in range(ACCOUNT_MAX_ATTEMPTS):
        _from(app, f"198.51.100.{i + 1}").post("/ztna/login", data={"username": "alice", "password": f"x-{i}yy"})
    response = _from(app, "203.0.113.50").post("/ztna/login", data={"username": "alice", "password": GOOD})
    assert "Too+many+failed+sign-ins" in response.headers["location"]
    assert guarded["helper"].ztna_status("203.0.113.50")["authorized"] is False
    # The webUI account of the same name is a different account.
    assert _from(app, "203.0.113.50").post("/login", data={"username": "boss", "password": GOOD}) \
        .headers["location"] == "/"


# -- password quality --------------------------------------------------------------------------


@pytest.mark.parametrize("password", ["password", "Password123!", "12345678", "qwertyuiop", "letmein2024",
                                      "iloveyou!!", "aaaaaaaaaa", "short"])
def test_weak_passwords_are_refused(password):
    from frfw import passwords

    assert passwords.problem(password) is not None


@pytest.mark.parametrize("password", [GOOD, "correct horse battery staple", "Tr0ub4dor&3x", "zebra-lamp-42"])
def test_reasonable_passwords_pass(password):
    from frfw import passwords

    assert passwords.problem(password) is None


def test_the_password_must_not_contain_the_username():
    from frfw import passwords

    assert "username" in passwords.problem("netadmin-2026x", "netadmin")


def test_every_way_of_setting_a_password_checks_it(guarded):
    app = create_app(**guarded)
    admin = _from(app, "192.168.1.10")
    admin.post("/login", data={"username": "boss", "password": GOOD})
    changed = admin.post("/account/password", data={"current_password": GOOD, "new_password": "Password123!",
                                                    "new_password_confirm": "Password123!"})
    assert "most+common" in changed.headers["location"]
    added = admin.post("/users/add", data={"new_username": "tech", "new_password": "qwerty123456", "role": "viewer"})
    assert "most+common" in added.headers["location"] and guarded["admin_store"].get("tech") is None
    guarded["admin_store"].add_user("guest", "violet-anchor-9", "viewer")
    reset = admin.post("/users/guest/password", data={"new_password": "letmein12345"})
    assert "most+common" in reset.headers["location"]
    assert guarded["admin_store"].verify("guest", "violet-anchor-9") is not None


def test_first_run_setup_refuses_a_common_password(webui_env):
    webui_env["admin_store"].set_password("admin", "generated-x7Kq2", ROLE_ADMIN, must_change=True)
    client = _from(create_app(**webui_env), "192.168.1.10")
    client.post("/login", data={"username": "admin", "password": "generated-x7Kq2"})
    response = client.post("/setup", data={"username": "owner", "password": "iloveyou1234",
                                           "password_confirm": "iloveyou1234"})
    assert "most+common" in response.headers["location"]
    assert set(webui_env["admin_store"].users()) == {"admin"}
