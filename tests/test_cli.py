import shutil

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
