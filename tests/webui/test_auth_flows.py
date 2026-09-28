"""Security-lessons J1: the auth flows tested as state machines.

Happy paths were well covered; what attackers use is the rest -- a step
skipped, requests out of order, a token or code used twice, two requests
racing. Each flow here is driven through those:

- sign-in with a second factor: every sequence (up to 3 steps) of the
  actions below is run against a model of what must be true afterwards;
- first-run setup, sessions, MFA enrolment, the ZTNA gate and privilege
  changes: skipped, reordered, replayed and parallel requests.
"""

from __future__ import annotations

import itertools
import threading
import time
from types import SimpleNamespace

import pyotp
import pytest
import yaml
from fastapi.testclient import TestClient

from frfw import admin_account
from frfw.admin_account import ROLE_ADMIN, ROLE_VIEWER, hash_password
from frfw.webui import mfa
from frfw.webui.app import create_app
from frfw.webui.auth import COOKIE_NAME
from frfw.webui.auth_rate_limiter import BruteforceGuard
from tests.webui.test_mfa import ORIGIN, SoftKey


@pytest.fixture(autouse=True)
def cheap_scrypt(monkeypatch):
    """The real hashing code with a lower cost, so hundreds of sign-ins
    stay fast (the parameters themselves are tested in test_password_hashing)."""
    monkeypatch.setattr(admin_account, "SCRYPT_N", 2**10)
    monkeypatch.setattr(admin_account, "_SCRYPT_MIN_COST", 2**10 * admin_account.SCRYPT_R * admin_account.SCRYPT_P)


def _client(app) -> TestClient:
    return TestClient(app, follow_redirects=False)


def _sign_in(app, username, password) -> TestClient:
    client = _client(app)
    response = client.post("/login", data={"username": username, "password": password})
    assert response.headers["location"] == "/", response.headers["location"]
    return client


def _signed_in(client: TestClient) -> bool:
    return client.get("/account").status_code == 200


def _race(*calls):
    """Run the calls at the same moment, each on its own thread (as the
    webUI's thread pool would); their results in order. A server error
    in any of them fails the test."""
    results, errors = [None] * len(calls), []
    barrier = threading.Barrier(len(calls))

    def run(i, call):
        barrier.wait()
        try:
            results[i] = call()
        except Exception as exc:  # noqa: BLE001 -- reported below
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(i, c)) for i, c in enumerate(calls)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert all(r is None or getattr(r, "status_code", 200) < 500 for r in results), results
    return results


# -- sign-in with a second factor, as a state machine ---------------------------------------------

ACTIONS = ("password", "wrong_password", "code", "wrong_code", "replayed_code", "logout")


class Model:
    """What must be true after each step."""

    def __init__(self) -> None:
        self.ticket = False  # a live login ticket in this browser
        self.attempts = 0
        self.session = False

    def step(self, action: str) -> None:
        if action == "password":
            self.ticket, self.attempts = True, 0  # a new ticket; no session from the password
        elif action == "code":
            if self.ticket:
                self.session, self.ticket = True, False
        elif action in ("wrong_code", "replayed_code"):
            if self.ticket:
                self.attempts += 1
                self.ticket = self.attempts < mfa.MAX_CODE_ATTEMPTS
        elif action == "logout":
            self.session = False


@pytest.fixture
def mfa_machine(webui_env, monkeypatch):
    store = webui_env["admin_store"]
    store.set_password("boss", "adminpass1", ROLE_ADMIN)
    secret = pyotp.random_base32()
    clock = SimpleNamespace(now=time.time())
    monkeypatch.setattr(mfa, "time", SimpleNamespace(time=lambda: clock.now))
    app = create_app(**webui_env)

    def run(sequence):
        # A fresh start: no tickets, no used codes, no failure history.
        app.state.mfa_tickets = mfa.TicketStore()
        app.state.bruteforce_guard = BruteforceGuard()
        store.set_mfa("boss", {"totp": {"secret": secret, "last_step": -1}})
        client, model, used = _client(app), Model(), []
        for action in sequence:
            if action == "password":
                client.post("/login", data={"username": "boss", "password": "adminpass1"})
            elif action == "wrong_password":
                client.post("/login", data={"username": "boss", "password": "wrong-pass1"})
            elif action == "code":
                clock.now += 30  # the next time step: a code never used before
                code = pyotp.TOTP(secret).at(clock.now)
                if client.post("/login/mfa/totp", data={"code": code}).headers["location"] == "/":
                    used.append(code)
            elif action == "wrong_code":
                valid = {pyotp.TOTP(secret).at(clock.now + d) for d in (-30, 0, 30)}
                client.post("/login/mfa/totp", data={"code": next(c for c in ("000000", "111111", "222222", "333333")
                                                                  if c not in valid)})
            elif action == "replayed_code":
                client.post("/login/mfa/totp", data={"code": used[-1] if used else pyotp.TOTP(secret).at(0)})
            elif action == "logout":
                client.post("/logout")
            model.step(action)
            where = f"{sequence} after {action}"
            assert _signed_in(client) == model.session, where
            assert (client.get("/login/mfa").status_code == 200) == model.ticket, where

    return run


def test_every_sign_in_sequence_matches_the_model(mfa_machine):
    sequences = [s for n in (1, 2, 3) for s in itertools.product(ACTIONS, repeat=n)]
    assert len(sequences) == 258
    for sequence in sequences:
        mfa_machine(sequence)


def test_the_longest_attack_sequences(mfa_machine):
    # Password, then the ticket burnt by wrong codes, then the right code: no session.
    mfa_machine(("password",) + ("wrong_code",) * mfa.MAX_CODE_ATTEMPTS + ("code",))
    # A code that signed in once can't sign in again after logout.
    mfa_machine(("password", "code", "logout", "password", "replayed_code", "replayed_code"))


def test_the_second_step_without_the_first_gets_nothing(app, webui_env):
    webui_env["admin_store"].set_password("boss", "adminpass1", ROLE_ADMIN)
    client = _client(app)
    assert client.get("/login/mfa").headers["location"].startswith("/login")
    assert client.post("/login/mfa/totp", data={"code": "123456"}).headers["location"].startswith("/login")
    assert client.post("/login/mfa/webauthn/options").status_code == 400
    assert client.post("/login/mfa/webauthn/verify", json={}).status_code == 400
    assert not _signed_in(client)


def test_a_ticket_is_useless_for_an_account_without_a_factor(app, webui_env):
    """A ticket taken while the account had a factor, which is then
    reset, can't turn into a session with any code."""
    store = webui_env["admin_store"]
    store.set_password("boss", "adminpass1", ROLE_ADMIN)
    store.set_mfa("boss", {"totp": {"secret": pyotp.random_base32(), "last_step": -1}})
    client = _client(app)
    client.post("/login", data={"username": "boss", "password": "adminpass1"})
    store.reset_mfa("boss")
    assert client.post("/login/mfa/totp", data={"code": "123456"}).headers["location"] != "/"
    assert not _signed_in(client)


# -- first-run setup ---------------------------------------------------------------------------------


@pytest.fixture
def generated(webui_env):
    store = webui_env["admin_store"]
    store.set_password("admin", "generated-pw-1", ROLE_ADMIN, must_change=True)
    return store


def test_setup_cannot_be_skipped(app, generated):
    client = _sign_in(app, "admin", "generated-pw-1")
    for path in ("/", "/rules", "/users", "/account", "/account/mfa", "/system"):
        assert client.get(path).headers.get("location") == "/setup", path
    for path in ("/rules/add", "/users/add", "/account/password", "/users/mfa-policy", "/account/mfa/remove"):
        assert client.post(path, data={}).headers.get("location") == "/setup", path


def test_setup_needs_a_session(app, generated):
    anonymous = _client(app)
    response = anonymous.post("/setup", data={"username": "alice", "password": "orchid-lamp-7",
                                              "password_confirm": "orchid-lamp-7"})
    assert response.headers["location"] == "/login"
    assert set(generated.users()) == {"admin"}


def test_setup_replayed_after_it_completed(app, generated):
    client = _sign_in(app, "admin", "generated-pw-1")
    old_cookie = client.cookies[COOKIE_NAME]
    form = {"username": "alice", "password": "orchid-lamp-7", "password_confirm": "orchid-lamp-7"}
    assert client.post("/setup", data=form).headers["location"] == "/"
    # The generated account's session ended; replaying it gets nothing.
    replay = _client(app)
    replay.cookies.set(COOKIE_NAME, old_cookie)
    assert replay.post("/setup", data={**form, "username": "mallory"}).headers["location"] == "/login"
    # The new session can't run setup again either.
    assert client.post("/setup", data={**form, "username": "mallory"}).headers["location"] == "/"
    assert set(generated.users()) == {"alice"}
    assert _client(app).post("/login", data={"username": "admin", "password": "generated-pw-1"}) \
        .headers["location"].startswith("/login?")


def test_parallel_setup_requests_create_one_account(app, generated):
    """Two tabs (or an attacker racing the owner) submitting setup at
    once: exactly one wins, the other gets an error, and nothing else is
    left behind."""
    clients = [_sign_in(app, "admin", "generated-pw-1") for _ in range(4)]
    results = dict(enumerate(_race(*[
        (lambda i=i, c=c: c.post("/setup", data={"username": f"owner{i}", "password": f"orchid-lamp-{i}x",
                                                  "password_confirm": f"orchid-lamp-{i}x"}))
        for i, c in enumerate(clients)])))
    winners = [i for i, r in results.items() if r.headers["location"] == "/"]
    assert len(winners) == 1, {i: r.headers["location"] for i, r in results.items()}
    assert set(generated.users()) == {f"owner{winners[0]}"}
    assert _signed_in(clients[winners[0]])
    for i, client in enumerate(clients):
        if i != winners[0]:
            assert not _signed_in(client)


def test_a_normal_account_cannot_use_setup_to_rename_itself(app, webui_env):
    store = webui_env["admin_store"]
    store.set_password("boss", "adminpass1", ROLE_ADMIN)
    store.set_password("guest", "viewerpass1", ROLE_VIEWER)
    for name, password in (("guest", "viewerpass1"), ("boss", "adminpass1")):
        client = _sign_in(app, name, password)
        client.post("/setup", data={"username": "root2", "password": "whatever12", "password_confirm": "whatever12"})
    assert set(store.users()) == {"guest", "boss"}
    assert store.get("guest").role == ROLE_VIEWER


# -- sessions --------------------------------------------------------------------------------------


def test_a_logged_out_session_cannot_change_anything(app, webui_env):
    store = webui_env["admin_store"]
    store.set_password("boss", "adminpass1", ROLE_ADMIN)
    client = _sign_in(app, "boss", "adminpass1")
    cookie = client.cookies[COOKIE_NAME]
    client.post("/logout")
    thief = _client(app)
    thief.cookies.set(COOKIE_NAME, cookie)
    for path, data in (("/users/add", {"new_username": "evil", "new_password": "evilpass1", "role": "admin"}),
                       ("/account/password", {"current_password": "adminpass1", "new_password": "x" * 10,
                                              "new_password_confirm": "x" * 10}),
                       ("/users/mfa-policy", {"require": "true"})):
        assert thief.post(path, data=data).headers["location"] == "/login", path
    assert set(store.users()) == {"boss"} and not store.policy()


def test_parallel_password_changes_leave_one_password(app, webui_env):
    store = webui_env["admin_store"]
    store.set_password("boss", "adminpass1", ROLE_ADMIN)
    clients = [_sign_in(app, "boss", "adminpass1") for _ in range(3)]
    _race(*[(lambda i=i, c=c: c.post("/account/password", data={
        "current_password": "adminpass1", "new_password": f"newpass-{i}xx", "new_password_confirm": f"newpass-{i}xx"}))
        for i, c in enumerate(clients)])
    working = [i for i in range(3) if store.verify("boss", f"newpass-{i}xx")]
    assert len(working) == 1 and store.verify("boss", "adminpass1") is None
    # Whatever order they landed in, no session outlived the last change but the one that made it.
    assert sum(_signed_in(c) for c in clients) <= 1


def test_concurrent_account_writes_are_not_lost(app, webui_env):
    """Admins adding users at the same moment: every account lands in
    auth.json (read-modify-write under one lock, also across processes)."""
    store = webui_env["admin_store"]
    store.set_password("boss", "adminpass1", ROLE_ADMIN)
    admin = _sign_in(app, "boss", "adminpass1")
    _race(*[(lambda i=i: admin.post("/users/add", data={"new_username": f"user{i}", "new_password": "userpass1",
                                                         "role": "viewer"}))
            for i in range(8)])
    assert set(store.users()) == {"boss"} | {f"user{i}" for i in range(8)}


# -- MFA enrolment out of order ------------------------------------------------------------------------


@pytest.fixture
def two_accounts(webui_env):
    store = webui_env["admin_store"]
    store.set_password("boss", "adminpass1", ROLE_ADMIN)
    store.set_password("guest", "viewerpass1", ROLE_VIEWER)
    return store


def test_enrolment_steps_out_of_order(two_accounts, webui_env):
    app_ = create_app(**webui_env)
    boss = TestClient(app_, base_url=ORIGIN, follow_redirects=False)
    boss.post("/login", data={"username": "boss", "password": "adminpass1"})
    # Registering a key with no options first.
    assert boss.post("/account/mfa/webauthn/register", json={"tid": "", "credential": {}}).status_code == 400
    # A TOTP confirmation that names a security-key enrolment.
    start = boss.post("/account/mfa/webauthn/options", json={"password": "adminpass1"}).json()
    confirm = boss.post("/account/mfa/totp", data={"tid": start["tid"], "code": "123456", "password": "adminpass1"})
    assert "error" in confirm.headers["location"]
    # The options of the key enrolment answered twice: only the first counts.
    key = SoftKey()
    answer = key.create(start["options"])
    assert boss.post("/account/mfa/webauthn/register", json={"tid": start["tid"], "credential": answer}).status_code == 200
    assert boss.post("/account/mfa/webauthn/register", json={"tid": start["tid"], "credential": answer}).status_code == 400
    assert len(two_accounts.get("boss").mfa["webauthn"]) == 1
    # Another account can't finish boss's enrolment.
    start = boss.post("/account/mfa/webauthn/options", json={"password": "adminpass1"}).json()
    guest = TestClient(app_, base_url=ORIGIN, follow_redirects=False)
    guest.post("/login", data={"username": "guest", "password": "viewerpass1"})
    stolen = guest.post("/account/mfa/webauthn/register",
                        json={"tid": start["tid"], "credential": SoftKey().create(start["options"])})
    assert stolen.status_code == 400 and not two_accounts.get("guest").has_mfa


def test_a_second_options_request_invalidates_the_first_challenge(two_accounts, webui_env):
    app_ = create_app(**webui_env)
    key = SoftKey()
    boss = TestClient(app_, base_url=ORIGIN, follow_redirects=False)
    boss.post("/login", data={"username": "boss", "password": "adminpass1"})
    start = boss.post("/account/mfa/webauthn/options", json={"password": "adminpass1"}).json()
    boss.post("/account/mfa/webauthn/register", json={"tid": start["tid"], "credential": key.create(start["options"])})
    boss.post("/logout")
    client = TestClient(app_, base_url=ORIGIN, follow_redirects=False)
    client.post("/login", data={"username": "boss", "password": "adminpass1"})
    first = client.post("/login/mfa/webauthn/options").json()
    client.post("/login/mfa/webauthn/options")  # a second request replaces the challenge
    assert client.post("/login/mfa/webauthn/verify", json=key.get(first)).status_code == 403
    assert not _signed_in(client)


# -- the ZTNA gate ---------------------------------------------------------------------------------------


@pytest.fixture
def ztna(webui_env):
    webui_env["config_path"].write_text(yaml.safe_dump({
        "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"},
                       "lan": {"device": "eth1", "zone": "lan", "address": "192.168.1.1/24"}},
        "rules": [], "nat": {"masquerade": [{"out_zone": "wan"}]},
        "ztna": {"enabled": True, "users": [{"username": "alice", "password_hash": hash_password("alice-pass-1")}]},
    }))
    return webui_env["helper"]


def test_ztna_status_without_signing_in_is_not_authorized(app, ztna):
    assert "authorized" in _client(app).get("/ztna/status").text
    assert ztna.ztna_status("testclient")["authorized"] is False


def test_ztna_wrong_then_right(app, ztna):
    client = _client(app)
    client.post("/ztna/login", data={"username": "alice", "password": "nope-nope"})
    assert ztna.ztna_status("testclient")["authorized"] is False
    client.post("/ztna/login", data={"username": "alice", "password": "alice-pass-1"})
    assert ztna.ztna_status("testclient")["authorized"] is True


def test_ztna_and_webui_failures_share_one_counter(app, ztna, webui_env):
    webui_env["admin_store"].set_password("boss", "adminpass1", ROLE_ADMIN)
    client = _client(app)
    for i in range(5):
        path = "/ztna/login" if i % 2 else "/login"
        client.post(path, data={"username": "alice" if i % 2 else "boss", "password": "wrong-pass"})
    assert ztna.banned and ztna.banned[0][0] == "testclient"


def test_parallel_ztna_logins_authorize_once_per_address(app, ztna):
    clients = [_client(app) for _ in range(4)]
    _race(*[(lambda c=c: c.post("/ztna/login", data={"username": "alice", "password": "alice-pass-1"}))
            for c in clients])
    status = ztna.ztna_status("testclient")
    assert status["authorized"] and status["username"] == "alice"


def test_a_disabled_gate_authorizes_nobody(app, ztna, webui_env):
    raw = yaml.safe_load(webui_env["config_path"].read_text())
    raw["ztna"]["enabled"] = False
    webui_env["config_path"].write_text(yaml.safe_dump(raw))
    _client(app).post("/ztna/login", data={"username": "alice", "password": "alice-pass-1"})
    assert ztna.ztna_status("testclient")["authorized"] is False


# -- privilege changes mid-session -------------------------------------------------------------------------


def test_a_demoted_admin_loses_admin_rights_on_the_next_request(app, two_accounts):
    two_accounts.add_user("boss2", "adminpass2", ROLE_ADMIN)
    session = _sign_in(app, "boss2", "adminpass2")
    assert session.get("/users").status_code == 200
    _sign_in(app, "boss", "adminpass1").post("/users/boss2/role", data={"role": ROLE_VIEWER})
    assert session.get("/users").status_code == 403
    assert session.post("/users/add", data={"new_username": "x", "new_password": "xxxxxxxx1",
                                            "role": "admin"}).status_code == 403
    assert "x" not in two_accounts.users()


def test_a_viewer_cannot_raise_itself(app, two_accounts):
    guest = _sign_in(app, "guest", "viewerpass1")
    for path, data in (("/users/guest/role", {"role": ROLE_ADMIN}), ("/users/mfa-policy", {"require": "true"}),
                       ("/users/boss/mfa-reset", {}), ("/users/boss/password", {"new_password": "taken-over1"})):
        assert guest.post(path, data=data).status_code == 403, path
    assert two_accounts.get("guest").role == ROLE_VIEWER
    assert two_accounts.verify("boss", "adminpass1") is not None


def test_the_account_lock_holds_across_processes(tmp_path):
    """`firewall-cli` (another process) and the webUI change the same
    file: a change waits while the other holds the lock."""
    import subprocess
    import sys

    from frfw.admin_account import AdminStore

    path = tmp_path / "auth.json"
    holder = ("import sys, time\nfrom pathlib import Path\nfrom frfw.admin_account import AdminStore\n"
              "with AdminStore(Path(sys.argv[1])).lock():\n    print('locked', flush=True)\n    time.sleep(1.5)\n")
    proc = subprocess.Popen([sys.executable, "-c", holder, str(path)], stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "locked"
        started = time.monotonic()
        AdminStore(path).set_password("boss", "adminpass1", ROLE_ADMIN)
        assert time.monotonic() - started >= 1.0
    finally:
        proc.wait(timeout=10)
    assert AdminStore(path).verify("boss", "adminpass1") is not None
