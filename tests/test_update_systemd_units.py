"""Static checks for the update mechanism's systemd units (phase 6).

Mirrors test_installer.py's approach for fr-first-boot.service: run the
units through the real `systemd-analyze verify` when available, skipped
otherwise.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SYSTEMD_DIR = REPO_ROOT / "systemd"

requires_systemd_analyze = pytest.mark.skipif(
    shutil.which("systemd-analyze") is None, reason="systemd-analyze not installed"
)


def test_unit_files_exist():
    assert (SYSTEMD_DIR / "fr-update-helper.socket").is_file()
    assert (SYSTEMD_DIR / "fr-update-helper.service").is_file()


@requires_systemd_analyze
@pytest.mark.parametrize(
    "unit",
    ["fr-update-helper.socket", "fr-update-helper.service"],
)
def test_unit_is_valid(unit: str):
    # Unlike fr-first-boot.service, ExecStart=firewall-update-helper
    # resolves against systemd's compiled search path without needing a
    # stub binary here: pip installs console_scripts entry points into
    # /usr/local/bin, which is already on that search path.
    proc = subprocess.run(
        ["systemd-analyze", "verify", str(SYSTEMD_DIR / unit)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
