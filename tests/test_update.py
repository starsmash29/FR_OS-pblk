"""Tests for frfw.update.

Every network call and every subprocess call goes through a small,
monkeypatchable seam (`_fetch_json`, `_download_tarball`, `_run`,
`_restart_webui_delayed`) -- these tests never touch a real socket or
spawn a real `pip`/`systemctl`, mirroring the pattern already used for
`frfw.apply._run_nft` in test_apply_backup.py / test_helper.py.
"""

from __future__ import annotations

import io
import json
import tarfile
import urllib.error

import pytest

from frfw import update as update_mod


# --- version parsing / comparison -----------------------------------------


@pytest.mark.parametrize("text", ["1.2.3", "v1.2.3", " v1.2.3 "])
def test_parse_version_accepts_with_or_without_v_prefix(text):
    assert update_mod.parse_version(text) == (1, 2, 3)


@pytest.mark.parametrize("text", ["", "1.2", "1.2.3.4", "vX.Y.Z", "1.2.3-rc1"])
def test_parse_version_rejects_malformed(text):
    with pytest.raises(update_mod.UpdateError):
        update_mod.parse_version(text)


# --- check_latest / list_releases ------------------------------------------


def _release_json(tag: str, body: str = "") -> dict:
    return {"tag_name": tag, "body": body, "published_at": "2026-01-01T00:00:00Z", "html_url": ""}


def test_check_latest_reports_update_available(monkeypatch):
    monkeypatch.setattr(update_mod, "_fetch_json", lambda url, timeout: _release_json("v0.2.0"))
    result = update_mod.check_latest("0.1.0", repo="x/y")
    assert result.update_available is True
    assert result.latest.version == "0.2.0"
    assert result.current_version == "0.1.0"


def test_check_latest_reports_up_to_date(monkeypatch):
    monkeypatch.setattr(update_mod, "_fetch_json", lambda url, timeout: _release_json("v0.1.0"))
    result = update_mod.check_latest("0.1.0", repo="x/y")
    assert result.update_available is False


def test_check_latest_older_latest_is_not_an_update(monkeypatch):
    monkeypatch.setattr(update_mod, "_fetch_json", lambda url, timeout: _release_json("v0.0.9"))
    result = update_mod.check_latest("0.1.0", repo="x/y")
    assert result.update_available is False


def test_check_latest_no_releases_yet_is_not_an_error(monkeypatch):
    def raise_404(url, timeout):
        raise urllib.error.HTTPError(url, 404, "Not Found", None, None)

    monkeypatch.setattr(update_mod, "_fetch_json", raise_404)
    result = update_mod.check_latest("0.1.0", repo="x/y")
    assert result.latest is None
    assert result.update_available is False


def test_check_latest_other_http_error_raises(monkeypatch):
    def raise_500(url, timeout):
        raise urllib.error.HTTPError(url, 500, "Server Error", None, None)

    monkeypatch.setattr(update_mod, "_fetch_json", raise_500)
    with pytest.raises(update_mod.UpdateError):
        update_mod.check_latest("0.1.0", repo="x/y")


def test_check_latest_non_semver_tag_falls_back_to_difference(monkeypatch):
    monkeypatch.setattr(update_mod, "_fetch_json", lambda url, timeout: _release_json("nightly"))
    result = update_mod.check_latest("0.1.0", repo="x/y")
    assert result.update_available is True
    assert result.latest.version == "nightly"


def test_list_releases_returns_newest_first_as_given(monkeypatch):
    monkeypatch.setattr(
        update_mod,
        "_fetch_json",
        lambda url, timeout: [_release_json("v0.2.0"), _release_json("v0.1.0")],
    )
    releases = update_mod.list_releases(repo="x/y")
    assert [r.version for r in releases] == ["0.2.0", "0.1.0"]


def test_list_releases_no_releases_yet_returns_empty(monkeypatch):
    def raise_404(url, timeout):
        raise urllib.error.HTTPError(url, 404, "Not Found", None, None)

    monkeypatch.setattr(update_mod, "_fetch_json", raise_404)
    assert update_mod.list_releases(repo="x/y") == []


# --- state persistence ------------------------------------------------------


def test_load_state_missing_file_returns_defaults(tmp_path):
    state = update_mod.load_state(current_version="0.1.0", path=tmp_path / "nope.json")
    assert state.current_version == "0.1.0"
    assert state.previous_version is None
    assert state.last_update == {}


def test_load_state_corrupt_file_returns_defaults(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("not json")
    state = update_mod.load_state(current_version="0.1.0", path=path)
    assert state.previous_version is None


def test_save_then_load_round_trips(tmp_path):
    path = tmp_path / "state.json"
    state = update_mod.UpdateState(
        current_version="0.2.0",
        previous_version="0.1.0",
        last_update={"action": "apply", "version": "0.2.0", "status": "success"},
    )
    update_mod.save_state(state, path)

    reloaded = update_mod.load_state(current_version="0.2.0", path=path)
    assert reloaded.previous_version == "0.1.0"
    assert reloaded.last_update["status"] == "success"


def test_load_state_current_version_argument_always_wins(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"current_version": "9.9.9", "previous_version": "0.1.0"}))
    state = update_mod.load_state(current_version="0.2.0", path=path)
    assert state.current_version == "0.2.0"
    assert state.previous_version == "0.1.0"


# --- path-traversal guard on extraction ------------------------------------


def _make_tarball(path, names: list[str]) -> None:
    with tarfile.open(path, "w:gz") as tar:
        for name in names:
            data = b"x"
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def test_safe_extract_rejects_path_traversal(tmp_path):
    tarball = tmp_path / "evil.tar.gz"
    _make_tarball(tarball, ["release-0.1.0/ok.txt", "../escaped.txt"])
    dest = tmp_path / "extract-here"
    with pytest.raises(update_mod.UpdateError, match="escapes"):
        update_mod._safe_extract(tarball, dest)


def test_safe_extract_normal_archive_returns_single_root_dir(tmp_path):
    tarball = tmp_path / "good.tar.gz"
    _make_tarball(tarball, ["release-0.1.0/pyproject.toml", "release-0.1.0/README.md"])
    dest = tmp_path / "extract-here"
    root = update_mod._safe_extract(tarball, dest)
    assert root.name == "release-0.1.0"
    assert (root / "pyproject.toml").is_file()


# --- apply_update / rollback_update (full flow, all I/O monkeypatched) -----


@pytest.fixture
def fake_release(tmp_path, monkeypatch):
    """Makes `_fetch_release` return a pre-built fake release directory
    (with a pyproject.toml so _fetch_release's cache check would also
    treat it as already-extracted) instead of downloading anything."""

    def _fetch(repo, version, releases_dir, timeout):
        release_dir = releases_dir / version
        release_dir.mkdir(parents=True, exist_ok=True)
        (release_dir / "pyproject.toml").write_text("[project]\n")
        (release_dir / "systemd").mkdir(exist_ok=True)
        (release_dir / "scripts").mkdir(exist_ok=True)
        return release_dir

    monkeypatch.setattr(update_mod, "_fetch_release", _fetch)
    return tmp_path


@pytest.fixture
def no_op_privileged_steps(monkeypatch):
    """`_install_release_dir`/`_restart_services`/`_restart_webui_delayed`
    all shell out; replace them with recorders so apply/rollback tests
    exercise real control flow without touching the real system."""
    calls = {"installed": [], "restarted": [], "webui_restart_scheduled": 0}

    monkeypatch.setattr(update_mod, "_install_release_dir", lambda d: calls["installed"].append(d))
    monkeypatch.setattr(update_mod, "_restart_services", lambda services: calls["restarted"].append(services))
    monkeypatch.setattr(
        update_mod, "_restart_webui_delayed", lambda: calls.__setitem__("webui_restart_scheduled", calls["webui_restart_scheduled"] + 1)
    )
    return calls


def test_apply_update_success_records_state_and_restarts(
    tmp_path, monkeypatch, fake_release, no_op_privileged_steps
):
    monkeypatch.setattr(update_mod, "_installed_version", lambda: "0.1.0")
    state_path = tmp_path / "state.json"
    releases_dir = tmp_path / "releases"

    new_version = update_mod.apply_update(
        "0.2.0", repo="x/y", state_path=state_path, releases_dir=releases_dir
    )

    assert new_version == "0.2.0"
    assert no_op_privileged_steps["webui_restart_scheduled"] == 1
    assert no_op_privileged_steps["restarted"] == [update_mod.SERVICES_TO_RESTART]

    state = update_mod.load_state(current_version="0.2.0", path=state_path)
    assert state.previous_version == "0.1.0"
    assert state.last_update["status"] == "success"
    assert state.last_update["action"] == "apply"


def test_apply_update_refuses_same_version(tmp_path, monkeypatch, fake_release, no_op_privileged_steps):
    monkeypatch.setattr(update_mod, "_installed_version", lambda: "0.1.0")
    with pytest.raises(update_mod.UpdateError, match="already running"):
        update_mod.apply_update(
            "0.1.0", state_path=tmp_path / "state.json", releases_dir=tmp_path / "releases"
        )
    assert no_op_privileged_steps["installed"] == []


def test_apply_update_failure_is_recorded_and_reraised(tmp_path, monkeypatch, fake_release):
    monkeypatch.setattr(update_mod, "_installed_version", lambda: "0.1.0")

    def boom(release_dir):
        raise update_mod.UpdateError("pip exploded")

    monkeypatch.setattr(update_mod, "_install_release_dir", boom)
    state_path = tmp_path / "state.json"

    with pytest.raises(update_mod.UpdateError, match="pip exploded"):
        update_mod.apply_update(
            "0.2.0", state_path=state_path, releases_dir=tmp_path / "releases"
        )

    state = update_mod.load_state(current_version="0.1.0", path=state_path)
    assert state.last_update["status"] == "failed"
    assert "pip exploded" in state.last_update["message"]
    # a failed apply must never advance current_version or previous_version
    assert state.previous_version is None


def test_rollback_update_without_previous_version_raises(tmp_path):
    with pytest.raises(update_mod.UpdateError, match="no previous version"):
        update_mod.rollback_update(
            state_path=tmp_path / "state.json", releases_dir=tmp_path / "releases"
        )


def test_rollback_update_success_restores_and_clears_previous(
    tmp_path, monkeypatch, fake_release, no_op_privileged_steps
):
    monkeypatch.setattr(update_mod, "_installed_version", lambda: "0.2.0")
    state_path = tmp_path / "state.json"
    update_mod.save_state(
        update_mod.UpdateState(current_version="0.2.0", previous_version="0.1.0"), state_path
    )

    restored = update_mod.rollback_update(state_path=state_path, releases_dir=tmp_path / "releases")

    assert restored == "0.1.0"
    state = update_mod.load_state(current_version="0.1.0", path=state_path)
    assert state.previous_version is None
    assert state.last_update["action"] == "rollback"
    assert state.last_update["status"] == "success"


def test_rollback_update_failure_is_recorded(tmp_path, monkeypatch, fake_release):
    monkeypatch.setattr(update_mod, "_installed_version", lambda: "0.2.0")
    state_path = tmp_path / "state.json"
    update_mod.save_state(
        update_mod.UpdateState(current_version="0.2.0", previous_version="0.1.0"), state_path
    )

    def boom(release_dir):
        raise update_mod.UpdateError("systemctl exploded")

    monkeypatch.setattr(update_mod, "_install_release_dir", boom)

    with pytest.raises(update_mod.UpdateError, match="systemctl exploded"):
        update_mod.rollback_update(state_path=state_path, releases_dir=tmp_path / "releases")

    state = update_mod.load_state(current_version="0.2.0", path=state_path)
    # a failed rollback must not lose the previous_version it needs to retry
    assert state.previous_version == "0.1.0"
    assert state.last_update["status"] == "failed"
