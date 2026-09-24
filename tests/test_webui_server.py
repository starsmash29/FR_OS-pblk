from __future__ import annotations

from pathlib import Path

from frfw.webui.server import _pqc_enabled


def _write_config(path: Path, extra: str = "") -> None:
    path.write_text(
        "version: 1\n"
        "hostname: fr-router\n"
        "zones:\n  wan: {}\n"
        "interfaces:\n  wan:\n    device: eth0\n    zone: wan\n"
        "rules: []\n" + extra
    )


def test_pqc_enabled_true(tmp_path):
    config_path = tmp_path / "config.yaml"
    _write_config(config_path, "pqc:\n  enabled: true\n")
    assert _pqc_enabled(config_path) is True


def test_pqc_enabled_false_by_default(tmp_path):
    config_path = tmp_path / "config.yaml"
    _write_config(config_path)
    assert _pqc_enabled(config_path) is False


def test_pqc_enabled_false_when_config_missing(tmp_path):
    assert _pqc_enabled(tmp_path / "does-not-exist.yaml") is False


def test_pqc_enabled_false_when_config_invalid(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("not: a valid frfw config at all\n")
    assert _pqc_enabled(config_path) is False
