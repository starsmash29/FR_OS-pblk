"""Static checks for the XDP SNI filter event logger's systemd unit
(phase 4). Mirrors test_update_systemd_units.py's approach: run the unit
through the real `systemd-analyze verify` when available, skipped
otherwise.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SYSTEMD_DIR = REPO_ROOT / "systemd"
UNIT = "fr-xdp-sni-logger.service"

requires_systemd_analyze = pytest.mark.skipif(
    shutil.which("systemd-analyze") is None, reason="systemd-analyze not installed"
)


def test_unit_file_exists():
    assert (SYSTEMD_DIR / UNIT).is_file()


@requires_systemd_analyze
def test_unit_is_valid():
    # ExecStart=fr-xdp-sni-logger resolves against systemd's compiled
    # search path without needing a stub binary here, the same as
    # test_update_systemd_units.py's fr-update-helper.service: pip
    # installs console_scripts entry points into /usr/local/bin, already
    # on that search path.
    proc = subprocess.run(
        ["systemd-analyze", "verify", str(SYSTEMD_DIR / UNIT)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
