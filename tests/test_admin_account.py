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
