"""Static checks for the phase 5 installer artifacts: the first-boot
script, the live-build config tree, and the systemd units they add.

These can't exercise a real install (that needs the actual ISO booted on
real or virtual hardware -- see installer/build-live-image.sh and
ROADMAP.md phase 5 for how that was verified manually), but they do
catch the class of mistake most likely to slip in silently: a typo'd
flag, a script that stops being executable, a shell syntax error.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
SYSTEMD_DIR = REPO_ROOT / "systemd"
LIVE_BUILD_DIR = REPO_ROOT / "installer" / "live-build"

requires_shellcheck = pytest.mark.skipif(
    shutil.which("shellcheck") is None, reason="shellcheck not installed"
)
requires_systemd_analyze = pytest.mark.skipif(
    shutil.which("systemd-analyze") is None, reason="systemd-analyze not installed"
)


def test_fr_first_boot_script_exists_and_is_executable():
    script = SCRIPTS_DIR / "fr-first-boot.sh"
    assert script.is_file()
    assert script.stat().st_mode & 0o111, "fr-first-boot.sh must be executable"


def test_live_build_auto_config_exists_and_is_executable():
    auto_config = LIVE_BUILD_DIR / "auto" / "config"
    assert auto_config.is_file()
    assert auto_config.stat().st_mode & 0o111, "auto/config must be executable"


def test_live_build_hook_exists_and_is_executable():
    hook = LIVE_BUILD_DIR / "config" / "hooks" / "0100-install-frfw.hook.chroot"
    assert hook.is_file()
    assert hook.stat().st_mode & 0o111, "the chroot hook must be executable"


def test_package_list_has_core_dependencies():
    package_list = LIVE_BUILD_DIR / "config" / "package-lists" / "frfw.list.chroot"
    packages = set(package_list.read_text().split())
    for expected in {"nftables", "kea-dhcp4-server", "python3-pip", "iproute2", "openssl"}:
        assert expected in packages


def test_the_image_carries_realtek_nic_firmware():
    """ROADMAP FND-4: live-build's own firmware collection is off, so the
    Realtek NIC firmware is listed explicitly, from non-free-firmware."""
    packages = set((LIVE_BUILD_DIR / "config" / "package-lists" / "frfw.list.chroot").read_text().split())
    assert "firmware-realtek" in packages
    config = (LIVE_BUILD_DIR / "auto" / "config").read_text()
    assert '--archive-areas "main contrib non-free non-free-firmware"' in config
    assert "--firmware-chroot false" in config


def test_the_image_is_built_with_debian_security_updates():
    """Review FR-003/C-02: this live-build writes a security suite that
    doesn't exist (hence --security false), so bookworm-security comes
    from config/archives -- into the build chroot and the finished image
    -- and a hook fails the build unless it's used and fully applied."""
    for stage in ("chroot", "binary"):
        lines = (LIVE_BUILD_DIR / "config" / "archives" / f"debian-security.list.{stage}").read_text().splitlines()
        assert "deb http://security.debian.org/debian-security bookworm-security main contrib non-free "\
               "non-free-firmware" in lines
    hooks = sorted(p.name for p in (LIVE_BUILD_DIR / "config" / "hooks").glob("*.hook.chroot"))
    assert hooks.index("0050-security-updates.hook.chroot") < hooks.index("0100-install-frfw.hook.chroot")
    hook = LIVE_BUILD_DIR / "config" / "hooks" / "0050-security-updates.hook.chroot"
    assert hook.stat().st_mode & 0o111
    text = hook.read_text()
    assert "apt-get -y -o Dpkg::Options::=--force-confold upgrade" in text
    assert "dist-upgrade | grep '^Inst'" in text and "exit 1" in text


def test_the_router_installs_security_updates_but_not_the_kernel():
    packages = set((LIVE_BUILD_DIR / "config" / "package-lists" / "frfw.list.chroot").read_text().split())
    assert "unattended-upgrades" in packages
    text = (LIVE_BUILD_DIR / "config" / "hooks" / "0050-security-updates.hook.chroot").read_text()
    assert 'APT::Periodic::Unattended-Upgrade "1";' in text
    # Only the security suite (the Debian default also takes point releases).
    assert "#clear Unattended-Upgrade::Origins-Pattern;" in text
    assert '"origin=Debian,codename=${distro_codename}-security,label=Debian-Security";' in text
    assert '"linux-image-";' in text and 'Unattended-Upgrade::Automatic-Reboot "false";' in text


def test_build_orchestration_script_exists_and_is_executable():
    script = REPO_ROOT / "installer" / "build-live-image.sh"
    assert script.is_file()
    assert script.stat().st_mode & 0o111


@requires_shellcheck
@pytest.mark.parametrize(
    "path",
    [
        SCRIPTS_DIR / "fr-first-boot.sh",
        SCRIPTS_DIR / "install-system-integration.sh",
        REPO_ROOT / "installer" / "build-live-image.sh",
    ],
)
def test_bash_scripts_pass_shellcheck(path: Path):
    proc = subprocess.run(["shellcheck", str(path)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@requires_shellcheck
@pytest.mark.parametrize(
    "path",
    [
        LIVE_BUILD_DIR / "auto" / "config",
        LIVE_BUILD_DIR / "config" / "hooks" / "0100-install-frfw.hook.chroot",
        LIVE_BUILD_DIR / "config" / "hooks" / "0050-security-updates.hook.chroot",
        SCRIPTS_DIR / "lock-requirements.sh",
        SCRIPTS_DIR / "build-xdp-object.sh",
    ],
)
def test_posix_sh_scripts_pass_shellcheck(path: Path):
    proc = subprocess.run(["shellcheck", "-s", "sh", str(path)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@requires_systemd_analyze
def test_fr_first_boot_service_is_valid():
    # systemd-analyze verify resolves unqualified ExecStart= commands
    # against systemd's own compiled-in search path, not $PATH -- so the
    # stub has to land in one of those real directories (unlike a normal
    # subprocess call, monkeypatching PATH has no effect here).
    stub_path = Path("/usr/local/sbin/fr-first-boot.sh")
    already_existed = stub_path.exists()
    if not already_existed:
        stub_path.write_text("#!/bin/sh\nexit 0\n")
        stub_path.chmod(0o755)

    try:
        proc = subprocess.run(
            ["systemd-analyze", "verify", str(SYSTEMD_DIR / "fr-first-boot.service")],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
    finally:
        if not already_existed:
            stub_path.unlink(missing_ok=True)
