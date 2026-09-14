import shutil
from pathlib import Path

import pytest
import yaml

from frfw.cli import main

requires_nft = pytest.mark.skipif(shutil.which("nft") is None, reason="nft binary not installed")


def test_validate_valid_config(example_config_path, capsys):
    exit_code = main(["validate", str(example_config_path)])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "OK" in out


def test_validate_invalid_config_returns_1(tmp_path, minimal_config_dict, capsys):
    del minimal_config_dict["hostname"]
    bad_config = tmp_path / "bad.yaml"
    bad_config.write_text(yaml.safe_dump(minimal_config_dict))

    exit_code = main(["validate", str(bad_config)])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "hostname" in err


def test_validate_missing_file_returns_1(tmp_path, capsys):
    exit_code = main(["validate", str(tmp_path / "nope.yaml")])
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "not found" in err.lower()


def test_render_prints_ruleset(example_config_path, capsys):
    exit_code = main(["render", str(example_config_path)])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "table inet fr_os" in out


@requires_nft
def test_apply_dry_run_does_not_touch_kernel_state(example_config_path, capsys):
    exit_code = main(["apply", str(example_config_path), "--dry-run"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "dry-run" in out.lower()


def test_detect_interfaces_runs(capsys):
    exit_code = main(["detect-interfaces", "--include-virtual"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "NAME" in out


def test_assign_interfaces_writes_valid_config(tmp_path):
    out_path = tmp_path / "generated.yaml"
    exit_code = main(
        [
            "assign-interfaces",
            "--wan",
            "eth0",
            "--lan",
            "eth1",
            "--opt",
            "dmz:eth2",
            "--out",
            str(out_path),
        ]
    )
    assert exit_code == 0
    assert out_path.exists()
    assert main(["validate", str(out_path)]) == 0


def test_assign_interfaces_refuses_to_overwrite_without_force(tmp_path):
    out_path = tmp_path / "generated.yaml"
    out_path.write_text("existing")

    exit_code = main(
        ["assign-interfaces", "--wan", "eth0", "--lan", "eth1", "--out", str(out_path)]
    )

    assert exit_code == 1
    assert out_path.read_text() == "existing"


def test_assign_interfaces_overwrites_with_force(tmp_path):
    out_path = tmp_path / "generated.yaml"
    out_path.write_text("existing")

    exit_code = main(
        [
            "assign-interfaces",
            "--wan",
            "eth0",
            "--lan",
            "eth1",
            "--out",
            str(out_path),
            "--force",
        ]
    )

    assert exit_code == 0
    assert "existing" not in out_path.read_text()


def test_assign_interfaces_rejects_malformed_opt(tmp_path, capsys):
    exit_code = main(
        [
            "assign-interfaces",
            "--wan",
            "eth0",
            "--lan",
            "eth1",
            "--opt",
            "not-a-mapping",
            "--out",
            str(tmp_path / "x.yaml"),
        ]
    )
    err = capsys.readouterr().err
    assert exit_code == 1
    assert "ZONE:DEVICE" in err


def test_rollback_list_prints_backups(monkeypatch, capsys):
    monkeypatch.setattr("frfw.cli.list_backups", lambda: [Path("/backups/ruleset-x.nft")])
    exit_code = main(["rollback", "--list"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "ruleset-x.nft" in out


def test_rollback_list_empty(monkeypatch, capsys):
    monkeypatch.setattr("frfw.cli.list_backups", lambda: [])
    exit_code = main(["rollback", "--list"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "No backups found" in out


def test_rollback_invokes_rollback_last(monkeypatch, capsys):
    monkeypatch.setattr("frfw.cli.rollback_last", lambda: Path("/backups/ruleset-y.nft"))
    exit_code = main(["rollback"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "ruleset-y.nft" in out
