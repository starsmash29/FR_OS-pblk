from frfw.admin_account import AdminStore, hash_password, verify_password


def test_hash_and_verify_round_trip():
    hashed = hash_password("hunter22")
    assert verify_password("hunter22", hashed)
    assert not verify_password("wrong", hashed)


def test_verify_rejects_garbage_stored_value():
    assert not verify_password("anything", "not-a-valid-hash")


def test_admin_store_lifecycle(tmp_path):
    store = AdminStore(tmp_path / "auth.json")
    assert not store.exists()
    assert not store.verify("admin", "whatever")

    store.set_password("admin", "hunter22")
    assert store.exists()
    assert store.verify("admin", "hunter22")
    assert not store.verify("admin", "wrong")
    assert not store.verify("someone-else", "hunter22")

    store.set_password("admin", "newpassword")
    assert not store.verify("admin", "hunter22")
    assert store.verify("admin", "newpassword")


def test_root_hands_the_file_to_the_state_directory_owner(tmp_path, monkeypatch):
    # firewall-cli set-admin-password runs as root; the webUI reads the
    # file as its own unprivileged user, which owns the state directory.
    import os

    from frfw import admin_account

    state_dir = tmp_path / "webui"
    state_dir.mkdir()
    chowns = []
    monkeypatch.setattr(admin_account.os, "geteuid", lambda: 0)
    monkeypatch.setattr(admin_account.os, "chown", lambda path, uid, gid: chowns.append((uid, gid)))
    AdminStore(state_dir / "auth.json").set_password("admin", "correct horse battery")
    st = os.stat(state_dir)
    assert chowns == [(st.st_uid, st.st_gid)]


def test_non_root_does_not_chown(tmp_path, monkeypatch):
    from frfw import admin_account

    monkeypatch.setattr(admin_account.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(admin_account.os, "chown", lambda *a: (_ for _ in ()).throw(AssertionError("chown")))
    AdminStore(tmp_path / "auth.json").set_password("admin", "correct horse battery")
