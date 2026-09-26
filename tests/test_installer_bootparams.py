"""The live image's boot configuration -- each check is a bug a real QEMU
boot of the ISO found (see ARCHITECTURE.md, "Booting the image for real")."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LB = REPO / "installer" / "live-build"
ISOLINUX = LB / "config" / "bootloaders" / "isolinux"


def _auto_config_option(name: str) -> str:
    text = (LB / "auto" / "config").read_text()
    match = re.search(rf'--{name} ("[^"]*"|\S+)', text)
    assert match, f"--{name} missing from auto/config"
    return shlex.split(match.group(1))[0]


def test_init_system_is_systemd():
    # live-build 3.0 defaults to sysvinit: every FR_OS unit would then be
    # dead weight and the router would boot into a bare Debian.
    assert _auto_config_option("initsystem") == "systemd"


def test_boot_options():
    options = _auto_config_option("bootappend-live").split()
    assert "persistence" in options  # frfw.persistence
    # no "user"/"live" account with sudo on a box that runs sshd
    nocomponents = next(o for o in options if o.startswith("live-config.nocomponents="))
    assert {"user-setup", "sudo"} <= set(nocomponents.split("=", 1)[1].split(","))
    # ...and no tty1 autologin into it (which then fails in a restart loop)
    assert "live-config.noautologin" in options
    assert "console=ttyS0,115200n8" in options  # headless boxes


def test_uefi_menu_uses_the_same_options_as_bios():
    grub = (LB / "config" / "includes.binary" / "boot" / "grub" / "grub.cfg").read_text()
    wanted = "boot=live config " + _auto_config_option("bootappend-live")
    linux_lines = [line.strip() for line in grub.splitlines() if line.strip().startswith("linux ")]
    assert linux_lines, "no kernel line in grub.cfg"
    for line in linux_lines:
        assert wanted in line, line


def test_isolinux_has_the_modules_syslinux_6_needs():
    # isolinux.bin 6.x loads ldlinux.c32 first, and vesamenu.c32 needs
    # libcom32/libutil; without them the BIOS boot stops at
    # "Failed to load ldlinux.c32".
    for name in ("isolinux.bin", "ldlinux.c32", "libcom32.c32", "libutil.c32", "vesamenu.c32"):
        assert (ISOLINUX / name).is_symlink() or (ISOLINUX / name).is_file(), name


def test_bios_menu_boots_by_itself():
    # syslinux "timeout 0" waits forever -- a headless router would never boot.
    timeout = re.search(r"^timeout\s+(\d+)", (ISOLINUX / "isolinux.cfg").read_text(), re.M)
    assert timeout and 0 < int(timeout.group(1)) <= 100


def test_persistence_unit_is_installed_and_runs_before_first_boot():
    hook = (LB / "config" / "hooks" / "0100-install-frfw.hook.chroot").read_text()
    assert "fr-persistence-setup.service" in hook
    assert "systemctl enable fr-persistence-setup.service" in hook
    unit = (REPO / "systemd" / "fr-persistence-setup.service").read_text()
    assert "Before=fr-first-boot.service" in unit
    assert "fr-persistence-setup.service" in (REPO / "systemd" / "fr-first-boot.service").read_text()
    packages = (LB / "config" / "package-lists" / "frfw.list.chroot").read_text().split()
    assert "fdisk" in packages  # sfdisk, for the persistence partition


def test_only_the_normal_entry_is_the_menu_default():
    # With "menu default" on the fail-safe entry too, vesamenu booted that
    # one: a single CPU (nosmp), no APIC, and a reboot that hangs.
    entries = re.split(r"^label ", (ISOLINUX / "live.cfg.in").read_text(), flags=re.M)[1:]
    defaults = [e.splitlines()[0] for e in entries if "menu default" in e]
    assert defaults == ["live-@FLAVOUR@"]


def test_packages_the_booted_image_turned_out_to_need():
    packages = (LB / "config" / "package-lists" / "frfw.list.chroot").read_text().split()
    assert "dbus" in packages  # systemd-logind: the power button shuts down cleanly
    assert "dnsmasq-base" in packages  # /usr/sbin/dnsmasq for fr-adblock-dns.service


def test_system_integration_works_without_a_repo_checkout():
    # On the image the script runs from /usr/local/sbin: no examples/ and
    # no systemd/ next to it. First boot failed on exactly that.
    script = (REPO / "scripts" / "install-system-integration.sh").read_text()
    assert '! -f "$REPO_ROOT/examples/config.yaml"' in script
    assert 'if [[ -d "$REPO_ROOT/systemd" ]]' in script


def test_units_that_apply_can_write_what_an_apply_writes():
    # ProtectSystem=full makes /etc read-only; the first apply on a real
    # boot died writing /etc/kea/kea-dhcp4.conf.
    for unit in ("fr-firewall", "fr-apply-helper", "fr-schedule-check"):
        text = (REPO / "systemd" / f"{unit}.service").read_text()
        paths = next(line for line in text.splitlines() if line.startswith("ReadWritePaths=")).split("=", 1)[1].split()
        assert {"/etc/fr_os", "/etc/kea"} <= set(paths), unit


def test_a_fresh_checkout_builds_the_tested_image():
    # CI builds from a clean checkout; without these pins it picked other
    # defaults than the tested build tree -- and firmware-chroot fetches
    # a Contents file Debian no longer serves (404, failed build).
    assert _auto_config_option("firmware-chroot") == "false"
    assert _auto_config_option("firmware-binary") == "false"
    assert _auto_config_option("initramfs") == "live-boot"
