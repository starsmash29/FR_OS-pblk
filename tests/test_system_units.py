"""Every systemd unit in systemd/ must be installed by both installers.

A unit that exists in the repo but is never copied to /etc/systemd/system
fails silently on a real router: fr-xdp-sni-logger.service was missing
from both installers until phase 16, so the XDP filter's event log (and
everything reading it) never ran on an installed system.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
UNITS = sorted(p.name for p in (REPO_ROOT / "systemd").glob("fr-*"))
INSTALL_SCRIPT = REPO_ROOT / "scripts" / "install-system-integration.sh"
LIVE_BUILD_HOOK = REPO_ROOT / "installer" / "live-build" / "config" / "hooks" / "0100-install-frfw.hook.chroot"

#: fr-first-boot only makes sense inside the live image.
_LIVE_IMAGE_ONLY = {"fr-first-boot.service"}


@pytest.mark.parametrize("unit", [u for u in UNITS if u not in _LIVE_IMAGE_ONLY])
def test_install_script_installs_unit(unit: str):
    assert f"systemd/{unit}" in INSTALL_SCRIPT.read_text()


@pytest.mark.parametrize("unit", UNITS)
def test_live_build_hook_installs_unit(unit: str):
    assert f"    {unit}" in LIVE_BUILD_HOOK.read_text()


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze not installed")
def test_appid_unit_is_valid():
    proc = subprocess.run(
        ["systemd-analyze", "verify", str(REPO_ROOT / "systemd" / "fr-appid.service")],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
