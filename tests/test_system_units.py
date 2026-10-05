"""Every systemd unit in systemd/ must be installed by both installers,
and every timer enabled by both.

A unit that exists in the repo but is never copied to /etc/systemd/system
fails silently on a real router: fr-xdp-sni-logger.service was missing
from both installers until phase 16, so the XDP filter's event log (and
everything reading it) never ran on an installed system. A timer that is
installed but never enabled fails just as silently: fr-adblock-refresh.timer
was, so the image never refreshed its block lists (ROADMAP SEC-21).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
UNITS = sorted(p.name for p in (REPO_ROOT / "systemd").glob("fr-*"))
INSTALL_SCRIPT = REPO_ROOT / "scripts" / "install-system-integration.sh"
LIVE_BUILD_HOOK = REPO_ROOT / "installer" / "live-build" / "config" / "hooks" / "0100-install-frfw.hook.chroot"
FIRST_BOOT = REPO_ROOT / "scripts" / "fr-first-boot.sh"
TIMERS = [u for u in UNITS if u.endswith(".timer")]

#: fr-first-boot and fr-persistence-setup only make sense inside the live
#: image; so do fr-kernel-confirm and fr-kernel-prepare, a kernel staged
#: on the persistence partition (ROADMAP SEC-14) -- an installed system
#: updates its kernel in place.
_LIVE_IMAGE_ONLY = {"fr-first-boot.service", "fr-persistence-setup.service", "fr-kernel-confirm.service",
                    "fr-kernel-prepare.service", "fr-kernel-prepare.timer"}


@pytest.mark.parametrize("unit", [u for u in UNITS if u not in _LIVE_IMAGE_ONLY])
def test_install_script_installs_unit(unit: str):
    assert f"systemd/{unit}" in INSTALL_SCRIPT.read_text()


@pytest.mark.parametrize("unit", UNITS)
def test_live_build_hook_installs_unit(unit: str):
    assert f"    {unit}" in LIVE_BUILD_HOOK.read_text()


def _first_boot_units() -> list[str]:
    """The units fr-first-boot.sh enables and starts: its `for unit in`
    list."""
    block = re.search(r"^for unit in \\\n(.*?)^do$", FIRST_BOOT.read_text(), re.M | re.S)
    assert block is not None, "fr-first-boot.sh's unit list not found"
    return [line.strip().rstrip("\\").strip() for line in block.group(1).splitlines() if line.strip()]


def test_the_first_boot_unit_list_is_read():
    units = _first_boot_units()
    assert "fr-firewall" in units and "fr-update-helper.socket" in units


@pytest.mark.parametrize("timer", TIMERS)
def test_first_boot_enables_timer(timer: str):
    """The image's routers get every timer from fr-first-boot.sh (the live
    build hook only installs them)."""
    assert timer in _first_boot_units()


@pytest.mark.parametrize("timer", [t for t in TIMERS if t not in _LIVE_IMAGE_ONLY])
def test_install_script_enables_timer(timer: str):
    assert re.search(rf"^\s*systemctl enable --now {re.escape(timer)}\b", INSTALL_SCRIPT.read_text(), re.M)


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze not installed")
@pytest.mark.parametrize("unit", ["fr-appid.service", "fr-tls-fp.service"])
def test_new_daemon_units_are_valid(unit):
    proc = subprocess.run(
        ["systemd-analyze", "verify", str(REPO_ROOT / "systemd" / unit)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_the_image_confirms_a_staged_kernels_boot_from_its_first_boot():
    """ROADMAP SEC-14: enabled by the image itself, not by fr-first-boot --
    a router that never finished first boot can still try a kernel."""
    assert re.search(r"^systemctl enable fr-kernel-confirm\.service$", LIVE_BUILD_HOOK.read_text(), re.M)


@pytest.mark.parametrize("installer", [LIVE_BUILD_HOOK, INSTALL_SCRIPT])
def test_both_installers_set_up_the_hardware_watchdog(installer):
    assert re.search(r"install -D -m 0644 \S*systemd/watchdog-fr_os\.conf\"? /etc/systemd/system\.conf\.d/"
                     r"fr_os-watchdog\.conf$", installer.read_text(), re.M)
    conf = (REPO_ROOT / "systemd" / "watchdog-fr_os.conf").read_text()
    assert re.search(r"^RuntimeWatchdogSec=30s$", conf, re.M)
