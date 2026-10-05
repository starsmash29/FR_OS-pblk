"""The live image's boot configuration -- each check is a bug a real QEMU
boot of the ISO found (see ARCHITECTURE.md, "Booting the image for real")."""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
LB = REPO / "installer" / "live-build"
ISOLINUX = LB / "config" / "bootloaders" / "isolinux"
GRUB_CFG = LB / "config" / "includes.binary" / "boot" / "grub" / "grub.cfg"


def _auto_config_option(name: str) -> str:
    text = "\n".join(
        line for line in (LB / "auto" / "config").read_text().splitlines() if not line.lstrip().startswith("#")
    )
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
    # live-boot keeps the image's /etc/network/interfaces instead of putting
    # a DHCP client on every port -- the LAN one flushed the router's address.
    assert "ip=frommedia" in options


def test_uefi_menu_uses_the_same_options_as_bios():
    grub = GRUB_CFG.read_text()
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


def _isolinux_entries() -> dict[str, str]:
    entries = re.split(r"^label ", (ISOLINUX / "live.cfg.in").read_text(), flags=re.M)[1:]
    return {e.splitlines()[0]: e for e in entries}


def test_only_the_grub_entry_is_the_menu_default():
    # With "menu default" on the fail-safe entry too, vesamenu booted that
    # one: a single CPU (nosmp), no APIC, and a reboot that hangs. The
    # default starts GRUB, so BIOS boots from the same menu as UEFI
    # (ROADMAP SEC-14).
    entries = _isolinux_entries()
    assert [label for label, e in entries.items() if "menu default" in e] == ["fr-os-grub"]
    assert re.search(r"^\s*linux /boot/grub/grub\.lnx$", entries["fr-os-grub"], re.M)
    # ...and the kernel can still be started without GRUB, from the menu.
    for label in ("live-@FLAVOUR@", "live-@FLAVOUR@-failsafe"):
        assert "kernel @KERNEL@" in entries[label]
        assert "boot=live config @LB_BOOTAPPEND_LIVE@" in entries[label]


def test_both_firmwares_say_which_grub_started_the_kernel():
    # installer/qemu-boot-test.py looks for it in the kernel command line.
    linux_lines = [line for line in GRUB_CFG.read_text().splitlines() if line.strip().startswith("linux ")]
    assert linux_lines and all(line.endswith(" fr_os.loader=grub-${grub_platform}") for line in linux_lines)


def test_grub_menu_on_the_serial_console_on_bios():
    text = GRUB_CFG.read_text()
    block = text.split('if [ "${grub_platform}" = "pc" ]; then', 1)[1].split("\nfi\n", 1)[0]
    assert "serial --unit=0 --speed=115200" in block
    assert "terminal_output console serial" in block and "terminal_input console serial" in block


def test_the_iso_script_builds_grub_for_bios():
    script = (REPO / "installer" / "make-hybrid-uefi-iso.sh").read_text()
    assert 'cat "$GRUB_PC_DIR/lnxboot.img" "$WORK_DIR/core.img" > "$BINARY_DIR/boot/grub/grub.lnx"' in script
    # The BIOS core image reads no modules from the medium: everything
    # grub.cfg calls is built in.
    modules = re.search(r'^GRUB_MODULES="([^"]+)"', script, re.M).group(1).split()
    commands = {"serial": "serial", "terminal_input": "terminal", "terminal_output": "terminal",
                "linux": "linux", "initrd": "linux", "[": "test", "search": "search"}
    used = {word for line in GRUB_CFG.read_text().splitlines() if not line.lstrip().startswith("#")
            for word in line.split()[:2]}
    for command, module in commands.items():
        if command in used:
            assert module in modules, command


@pytest.mark.skipif(shutil.which("grub-script-check") is None, reason="grub-script-check not installed")
def test_grub_menu_parses():
    proc = subprocess.run(["grub-script-check", str(GRUB_CFG)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr


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
        assert {"/etc/fr_os", "/etc/kea"} <= {p.lstrip("-") for p in paths}, unit


def test_a_fresh_checkout_builds_the_tested_image():
    # CI builds from a clean checkout; without these pins it picked other
    # defaults than the tested build tree -- and firmware-chroot fetches
    # a Contents file Debian no longer serves (404, failed build).
    assert _auto_config_option("firmware-chroot") == "false"
    assert _auto_config_option("firmware-binary") == "false"
    assert _auto_config_option("initramfs") == "live-boot"


def test_only_the_wan_port_gets_a_dhcp_client():
    """The image's interfaces file is loopback only; fr-first-boot writes
    the WAN port's DHCP client and never one for the LAN port."""
    hook = (LB / "config" / "hooks" / "0100-install-frfw.hook.chroot").read_text()
    interfaces = hook.split("cat > /etc/network/interfaces <<'CONF'", 1)[1].split("\nCONF\n", 1)[0]
    assert "iface lo inet loopback" in interfaces and "inet dhcp" not in interfaces
    script = (LB.parents[1] / "scripts" / "fr-first-boot.sh").read_text()
    assert 'write_dhcp_clients "$WAN"' in script
    assert 'write_dhcp_clients "$LAN"' not in script and "inet manual" not in script
