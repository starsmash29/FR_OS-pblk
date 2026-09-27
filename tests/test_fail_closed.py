"""A2 (review triage): the firewall fails closed.

Before: fr-firewall.service was skipped without /etc/fr_os/config.yaml
(kernel default: accept everything), an apply that failed before reaching
nft left nothing loaded, and `ExecStop=nft flush ruleset` emptied the
firewall on every stop or restart.
"""

from __future__ import annotations

import configparser
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from frfw import apply as apply_mod
from frfw import cli
from frfw.apply import BASELINE_RULESET

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_CONFIG = REPO_ROOT / "examples" / "config.yaml"


@pytest.fixture
def kernel(monkeypatch):
    """A fake kernel: what `nft -f` loaded last, and whether our table is in."""
    state = {"loaded": [], "table": False}

    def run_nft(args, stdin):
        if args == ["-f", "-"]:
            state["loaded"].append(stdin)
            state["table"] = True

    monkeypatch.setattr(apply_mod, "_run_nft", run_nft)
    monkeypatch.setattr(apply_mod, "fr_os_table_loaded", lambda: state["table"])
    monkeypatch.setattr(apply_mod, "capture_running_ruleset", lambda: "")
    monkeypatch.setattr("os.geteuid", lambda: 0)
    return state


def test_no_config_loads_the_baseline(kernel, tmp_path, capsys):
    assert cli.main(["apply", "--fail-closed", str(tmp_path / "missing.yaml")]) == 0
    assert kernel["loaded"] == [BASELINE_RULESET]
    assert "fail-closed baseline loaded" in capsys.readouterr().out


def test_without_the_flag_a_missing_config_is_still_just_an_error(kernel, tmp_path):
    assert cli.main(["apply", str(tmp_path / "missing.yaml")]) == 1
    assert kernel["loaded"] == []


def test_a_failed_apply_with_nothing_loaded_loads_the_baseline(kernel, tmp_path):
    bad = tmp_path / "config.yaml"
    bad.write_text("version: 1\nzones: {}\ninterfaces: {wan: {device: eth0, zone: nowhere}}\n")
    assert cli.main(["apply", "--fail-closed", str(bad)]) == 1
    assert kernel["loaded"] == [BASELINE_RULESET]


def test_a_failed_apply_never_replaces_a_working_ruleset(kernel, tmp_path):
    kernel["table"] = True  # the last good apply is still in the kernel
    bad = tmp_path / "config.yaml"
    bad.write_text("version: 1\nzones: {}\ninterfaces: {wan: {device: eth0, zone: nowhere}}\n")
    assert cli.main(["apply", "--fail-closed", str(bad)]) == 1
    assert kernel["loaded"] == []


def test_dry_run_never_loads_anything(kernel, tmp_path):
    assert cli.main(["apply", "--dry-run", "--fail-closed", str(tmp_path / "missing.yaml")]) == 1
    assert kernel["loaded"] == []


def _unit(name: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read(REPO_ROOT / "systemd" / name)
    return parser


def test_unit_runs_without_a_config_and_never_flushes_on_stop():
    unit = _unit("fr-firewall.service")
    assert "ConditionPathExists" not in unit["Unit"]
    assert "--fail-closed" in unit["Service"]["ExecStart"]
    assert "--fail-closed" in unit["Service"]["ExecReload"]
    assert "ExecStop" not in unit["Service"]
    # A missing optional directory must not stop even the baseline.
    assert all(p.startswith("-") for p in unit["Service"]["ReadWritePaths"].split())


def test_the_image_enables_the_firewall_from_the_first_boot():
    hook = (REPO_ROOT / "installer/live-build/config/hooks/0100-install-frfw.hook.chroot").read_text()
    assert "systemctl enable fr-firewall.service" in hook
    # ...so first boot must *re*start it once the config exists.
    assert 'systemctl restart "$unit"' in (REPO_ROOT / "scripts/fr-first-boot.sh").read_text()


@pytest.mark.skipif(
    os.geteuid() != 0 or not shutil.which("nft") or not shutil.which("unshare"),
    reason="needs root, nft and unshare to load the baseline in a throwaway network namespace",
)
def test_baseline_loads_in_a_real_kernel_with_drop_policies():
    proc = subprocess.run(
        ["unshare", "--net", "sh", "-c", "nft -f - && nft list ruleset"],
        input=BASELINE_RULESET, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    listing = proc.stdout
    assert "hook input priority filter; policy drop;" in listing
    assert "hook forward priority filter; policy drop;" in listing
    assert 'iif "lo" accept' in listing
