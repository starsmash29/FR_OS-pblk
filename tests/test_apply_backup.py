"""Unit tests for frfw.apply's backup/rollback bookkeeping.

`_run_nft` and `capture_running_ruleset` are monkeypatched throughout so
these tests never touch the real kernel nftables state -- that would make
the test suite mutate whatever machine it runs on. The generated-ruleset
tests in test_builder.py already cover real `nft -c` validation.
"""

from __future__ import annotations

import pytest

from frfw import apply as apply_mod


@pytest.fixture(autouse=True)
def _pretend_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)


def test_apply_backs_up_previous_ruleset(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(apply_mod, "capture_running_ruleset", lambda: "table inet old {}\n")
    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: calls.append((args, stdin)))

    backup_dir = tmp_path / "backups"
    result = apply_mod.apply_ruleset(
        "new-ruleset-text", backup_dir=backup_dir, backup_retention=2
    )

    assert result.applied
    assert result.backup_path is not None
    backup_text = result.backup_path.read_text()
    assert backup_text.startswith("flush ruleset")
    assert "table inet old {}" in backup_text
    assert calls[-1] == (["-f", "-"], "new-ruleset-text")


def test_apply_skips_backup_when_nothing_was_running(tmp_path, monkeypatch):
    monkeypatch.setattr(apply_mod, "capture_running_ruleset", lambda: "")
    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: None)

    backup_dir = tmp_path / "backups"
    result = apply_mod.apply_ruleset("ruleset", backup_dir=backup_dir)

    assert result.backup_path is None
    assert not backup_dir.exists()


def test_apply_requires_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: None)

    with pytest.raises(apply_mod.NftError, match="root"):
        apply_mod.apply_ruleset("ruleset")


def test_dry_run_never_backs_up_or_requires_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)  # not root
    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: None)
    called = []
    monkeypatch.setattr(
        apply_mod, "capture_running_ruleset", lambda: called.append(1) or ""
    )

    result = apply_mod.apply_ruleset("ruleset", dry_run=True)

    assert not result.applied
    assert called == []  # never even asked for the current state


def test_backup_pruning_keeps_only_retention_count(tmp_path):
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    for i in range(5):
        (backup_dir / f"ruleset-2024010{i}T000000Z.nft").write_text("x")

    apply_mod._prune_backups(backup_dir, retention=2)

    remaining = sorted(p.name for p in backup_dir.glob("ruleset-*.nft"))
    assert remaining == ["ruleset-20240103T000000Z.nft", "ruleset-20240104T000000Z.nft"]


def test_rollback_last_loads_most_recent_backup(tmp_path, monkeypatch):
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    (backup_dir / "ruleset-20240101T000000Z.nft").write_text("old")
    newest = backup_dir / "ruleset-20240102T000000Z.nft"
    newest.write_text("newer")

    calls = []
    monkeypatch.setattr(apply_mod, "_run_nft", lambda args, stdin: calls.append(args))

    restored = apply_mod.rollback_last(backup_dir)

    assert restored == newest
    assert calls == [["-f", str(newest)]]


def test_rollback_without_backups_raises(tmp_path):
    with pytest.raises(apply_mod.NftError, match="No ruleset backups"):
        apply_mod.rollback_last(tmp_path / "empty")


def test_rollback_requires_root(tmp_path, monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    (backup_dir / "ruleset-20240101T000000Z.nft").write_text("old")

    with pytest.raises(apply_mod.NftError, match="root"):
        apply_mod.rollback_last(backup_dir)
