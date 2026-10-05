"""The image's boot chain, booted for real under BIOS and UEFI firmware
(ROADMAP SEC-14).

installer/make-hybrid-uefi-iso.sh -- the script the image build runs --
packs a small live-build tree into a hybrid ISO here: the repository's
own isolinux menu (config/bootloaders/isolinux, rendered the way
live-build renders it) and its own GRUB menu
(config/includes.binary/boot/grub/grub.cfg). QEMU then boots that ISO
with SeaBIOS and with OVMF, from a stick that has the persistence
partition frfw.persistence appends to it, and from a CD.

Everything up to the kernel is the real thing: the firmware, isolinux and
its default entry, GRUB's core image (BIOS) or EFI binary (UEFI), the
search for the ISO by its label, the menu and its default entry. There is
no kernel in the tree, so GRUB's `linux` and `initrd` are replaced by GRUB
functions that print what the menu entry handed them and power the VM off
-- the kernel command line each firmware would boot is checked argument
by argument. (GRUB runs a command before a function of the same name, so
the probe unloads the `linux` module first, with `rmmod` from a module the
test puts on its ISO: the image's GRUB has no `rmmod` built in.) installer/qemu-boot-test.py boots the real image both ways.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from frfw import kernel_boot, persistence

REPO = Path(__file__).resolve().parent.parent
LB = REPO / "installer" / "live-build"
ISOLINUX = LB / "config" / "bootloaders" / "isolinux"
GRUB_CFG = LB / "config" / "includes.binary" / "boot" / "grub" / "grub.cfg"
ISOHDPFX = Path("/usr/lib/ISOLINUX/isohdpfx.bin")
#: Debian 12 / Ubuntu 24.04 name them with _4M; older releases without.
OVMF = [(Path("/usr/share/OVMF") / f"OVMF_CODE{s}.fd", Path("/usr/share/OVMF") / f"OVMF_VARS{s}.fd")
        for s in ("_4M", "")]
#: live-build's LB_BOOTAPPEND_FAILSAFE (config/binary).
FAILSAFE = "memtest noapic noapm nodma nomce nolapic nomodeset nosmp nosplash vga=normal"
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

#: Put in front of the real grub.cfg: what the menu entry would boot,
#: one argument per line (a long line would be wrapped by the console).
PROBE = """\
insmod minicmd
rmmod linux
function linux {
    echo "FROS-PROBE linux"
    for arg in "$@"; do
        echo "FROS-ARG $arg"
    done
}
function initrd {
    echo "FROS-PROBE initrd $1"
    halt
}
"""

TOOLS = ("grub-mkstandalone", "grub-mkimage", "mkfs.vfat", "mmd", "mcopy", "xorriso", "sfdisk",
         "qemu-system-x86_64", "mkfs.ext4", "debugfs")
missing = [t for t in TOOLS if shutil.which(t) is None]
pytestmark = pytest.mark.skipif(
    bool(missing) or not ISOHDPFX.is_file() or not Path("/usr/lib/grub/i386-pc/lnxboot.img").is_file()
    or not Path("/usr/lib/grub/x86_64-efi/minicmd.mod").is_file()
    or not all(p.resolve().is_file() for p in ISOLINUX.iterdir()),
    reason=f"needs {', '.join(missing) or 'isolinux, syslinux and grub-pc-bin'}",
)


def _bootappend_live() -> str:
    text = "\n".join(line for line in (LB / "auto" / "config").read_text().splitlines()
                     if not line.lstrip().startswith("#"))
    return shlex.split(re.search(r'--bootappend-live ("[^"]*")', text).group(1))[0]


def _render_live_cfg(template: str) -> str:
    """live-build's lb_binary_syslinux: live.cfg.in -> live.cfg."""
    for name, value in (("@FLAVOUR@", "amd64"), ("@KERNEL@", "/live/vmlinuz"), ("@INITRD@", "/live/initrd.img"),
                        ("@LB_BOOTAPPEND_LIVE@", _bootappend_live()), ("@LB_BOOTAPPEND_FAILSAFE@", FAILSAFE)):
        template = template.replace(name, value)
    assert "@" not in template, template
    return template


@pytest.fixture(scope="module")
def iso(tmp_path_factory) -> Path:
    lb = tmp_path_factory.mktemp("lb")
    binary = lb / "binary"
    (binary / "isolinux").mkdir(parents=True)
    for path in ISOLINUX.iterdir():
        if path.name == "live.cfg.in":
            (binary / "isolinux" / "live.cfg").write_text(_render_live_cfg(path.read_text()))
        else:
            shutil.copyfile(path.resolve(), binary / "isolinux" / path.name)
    (binary / "boot" / "grub").mkdir(parents=True)
    (binary / "boot" / "grub" / "grub.cfg").write_text(PROBE + GRUB_CFG.read_text())
    # For the probe's `insmod minicmd` only: the same GRUB build the
    # script makes the images from.
    for platform in ("i386-pc", "x86_64-efi"):
        shutil.copytree(Path("/usr/lib/grub") / platform, binary / "boot" / "grub" / platform)
    (lb / "config").mkdir()
    (lb / "config" / "binary").write_text(
        'LB_BOOTLOADER="syslinux"\nLB_ISO_VOLUME="FR_OS"\nLB_ISO_APPLICATION="FR_OS"\n'
        'LB_ISO_PUBLISHER="tests/test_boot_chain.py"\n'
    )
    (lb / "chroot" / "usr" / "lib" / "ISOLINUX").mkdir(parents=True)
    shutil.copyfile(ISOHDPFX, lb / "chroot" / "usr" / "lib" / "ISOLINUX" / "isohdpfx.bin")
    proc = subprocess.run([str(REPO / "installer" / "make-hybrid-uefi-iso.sh")], capture_output=True, text=True,
                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "FROS_LB_DIR": str(lb)})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return lb / "binary.hybrid.iso"


def _stick(iso: Path, where: Path) -> Path:
    """The ISO written to a stick, with the persistence partition
    frfw.persistence.create_on_boot_medium appends after it (no file
    system on it yet: _persistence_fs makes one)."""
    stick = where / "stick.img"
    shutil.copyfile(iso, stick)
    with stick.open("r+b") as fh:
        fh.truncate(64 * 2**20)
    table = subprocess.run(["sfdisk", "--json", str(stick)], capture_output=True, text=True, check=True).stdout
    space = persistence.free_space_after_last_partition(table, stick.stat().st_size)
    subprocess.run(["sfdisk", "--append", "--no-reread", "--no-tell-kernel", str(stick)], check=True,
                   capture_output=True, text=True,
                   input=f"start={space.start // space.sector_size}, type={'L' if space.table == 'gpt' else '83'}\n")
    numbers = [p["node"] for p in json.loads(subprocess.run(["sfdisk", "--json", str(stick)], capture_output=True,
                                                            text=True, check=True).stdout)["partitiontable"]["partitions"]]
    assert numbers[-1].endswith("3")  # where live-boot and verify-medium look for it
    return stick


def _partition_3(stick: Path) -> tuple[int, int]:
    table = json.loads(subprocess.run(["sfdisk", "--json", str(stick)], capture_output=True, text=True,
                                      check=True).stdout)["partitiontable"]
    part = table["partitions"][-1]
    return part["start"] * table["sectorsize"], part["size"] * table["sectorsize"]


def _persistence_fs(stick: Path, root: Path) -> None:
    """Partition 3 becomes an ext4 file system labelled "persistence"
    (as frfw.persistence makes it) holding the tree `root`."""
    start, size = _partition_3(stick)
    image = stick.with_name("persistence.ext4")
    image.unlink(missing_ok=True)
    subprocess.run(["mkfs.ext4", "-q", "-F", "-L", persistence.LABEL, "-d", str(root), str(image),
                    f"{size // 1024}k"], check=True, capture_output=True)
    with stick.open("r+b") as fh:
        fh.seek(start)
        fh.write(image.read_bytes())


def _grubenv(stick: Path) -> dict[str, str]:
    """The block GRUB left on the stick's persistence partition."""
    start, size = _partition_3(stick)
    image = stick.with_name("persistence.ext4")
    with stick.open("rb") as fh:
        fh.seek(start)
        image.write_bytes(fh.read(size))
    proc = subprocess.run(["debugfs", "-R", f"cat /{kernel_boot.BOOT_DIR_NAME}/{kernel_boot.ENV_NAME}", str(image)],
                          capture_output=True, check=True)
    return kernel_boot.parse_env(proc.stdout)


def _boot(medium: Path, *, firmware: str, cdrom: bool, where: Path, name: str = "") -> str:
    serial = where / f"{firmware}-{'cd' if cdrom else 'stick'}{name}.log"
    cmd = ["qemu-system-x86_64", "-m", "512", "-display", "none", "-no-reboot", "-nic", "none",
           "-serial", f"file:{serial}"]
    if cdrom:
        cmd += ["-drive", f"if=none,id=medium,media=cdrom,readonly=on,format=raw,file={medium}",
                "-device", "ide-cd,drive=medium,bootindex=0"]
    else:
        cmd += ["-drive", f"if=none,id=medium,format=raw,file={medium}",
                "-device", "virtio-blk-pci,drive=medium,bootindex=0"]
    if firmware == "uefi":
        code, variables = next((c, v) for c, v in OVMF if c.is_file() and v.is_file())
        if not (where / "vars.fd").exists():  # one machine, booted again and again
            shutil.copyfile(variables, where / "vars.fd")
        cmd += ["-drive", f"if=pflash,format=raw,readonly=on,file={code}",
                "-drive", f"if=pflash,format=raw,file={where / 'vars.fd'}"]
    try:
        subprocess.run(cmd, capture_output=True, timeout=240)
    except subprocess.TimeoutExpired:
        pass  # what it got to is in the log
    return ANSI.sub("", serial.read_text(errors="replace")).replace("\r", "")


@pytest.mark.parametrize("cdrom", [False, True], ids=["stick", "cd"])
@pytest.mark.parametrize("firmware", ["bios", "uefi"])
def test_both_firmwares_boot_the_default_entry_of_one_grub_menu(iso, tmp_path, firmware, cdrom):
    if firmware == "uefi" and not any(c.is_file() and v.is_file() for c, v in OVMF):
        pytest.skip("needs OVMF (the ovmf package)")
    medium = iso if cdrom else _stick(iso, tmp_path)
    log = _boot(medium, firmware=firmware, cdrom=cdrom, where=tmp_path)
    assert "FROS-PROBE linux" in log, log[-3000:]
    args = re.findall(r"^FROS-ARG (\S+)$", log.split("FROS-PROBE linux", 1)[1], re.M)
    loader = "grub-pc" if firmware == "bios" else "grub-efi"
    # The default entry -- not the fail-safe one -- with the options the
    # BIOS menu had before GRUB came in front of it; nothing staged
    # (ROADMAP SEC-14), so the image's own kernel.
    assert _image_kernel_line(args, loader, "image"), log[-3000:]
    assert "FROS-PROBE initrd /live/initrd.img" in log


# -- a kernel staged on the persistence partition (ROADMAP SEC-14) ----------------------

#: Enough of a kernel for frfw.kernel_boot.stage(): the setup header's
#: magic. GRUB never loads it here -- the probe stands in for `linux`.
FAKE_KERNEL = b"\0" * 0x202 + b"HdrS" + b"k" * 4096


def _kernel_args(log: str) -> list[str]:
    assert "FROS-PROBE linux" in log, log[-3000:]
    return re.findall(r"^FROS-ARG (\S+)$", log.split("FROS-PROBE linux", 1)[1], re.M)


def _staged_stick(iso: Path, where: Path, *, state: str | None = None, damage: bool = False) -> Path:
    """A stick whose persistence partition has a kernel staged by
    frfw.kernel_boot.stage() -- in state `state` instead of "trial", or
    with its initrd damaged after its hashes were taken."""
    stick = _stick(iso, where)
    root = where / "persistence-root"
    (root / "rw").mkdir(parents=True)
    (root / "persistence.conf").write_text(persistence.CONF_CONTENT)
    (where / "vmlinuz-new").write_bytes(FAKE_KERNEL)
    (where / "initrd-new").write_bytes(b"initrd" * 1000)
    boot_dir = root / kernel_boot.BOOT_DIR_NAME
    kernel_boot.stage(where / "vmlinuz-new", where / "initrd-new", "6.1.0-99-amd64", boot_dir=boot_dir)
    if state:
        kernel_boot.write_env(boot_dir / kernel_boot.ENV_NAME,
                              {kernel_boot.STATE: state, kernel_boot.STAGED: "6.1.0-99-amd64"})
    if damage:
        (boot_dir / kernel_boot.SLOT / kernel_boot.INITRD).write_bytes(b"damaged" * 1000)
    _persistence_fs(stick, root)
    return stick


def _staged_kernel_line(args: list[str], loader: str, mode: str) -> bool:
    return (args[0].endswith(f"/{kernel_boot.BOOT_DIR_NAME}/{kernel_boot.SLOT}/{kernel_boot.KERNEL}")
            and args[1:] == ["boot=live", "config", *_bootappend_live().split(), f"fr_os.loader={loader}",
                             f"fr_os.kernel={mode}", "panic=10"])


def _image_kernel_line(args: list[str], loader: str, mode: str) -> bool:
    return args == ["/live/vmlinuz", "boot=live", "config", *_bootappend_live().split(), f"fr_os.loader={loader}",
                    f"fr_os.kernel={mode}"]


def _needs(firmware: str) -> None:
    if firmware == "uefi" and not any(c.is_file() and v.is_file() for c, v in OVMF):
        pytest.skip("needs OVMF (the ovmf package)")


@pytest.mark.parametrize("firmware", ["bios", "uefi"])
def test_a_staged_kernel_is_tried_once_then_the_images_kernel_boots(iso, tmp_path, firmware):
    """Its trial boot never confirms (a panic, a hang): the next boot is
    the image's kernel, marked as a fallback, and the one after it too."""
    _needs(firmware)
    loader = "grub-pc" if firmware == "bios" else "grub-efi"
    stick = _staged_stick(iso, tmp_path)
    assert _grubenv(stick) == {"fr_os_state": "trial", "fr_os_staged": "6.1.0-99-amd64"}

    log = _boot(stick, firmware=firmware, cdrom=False, where=tmp_path, name="-1")
    assert _staged_kernel_line(_kernel_args(log), loader, "trial"), log[-3000:]
    assert re.search(r"^FROS-PROBE initrd \S+/fr_os-boot/staged/initrd\.img$", log, re.M), log[-3000:]
    # Written before the kernel ran, so a kernel that never comes back
    # is not tried again.
    assert _grubenv(stick)["fr_os_state"] == "trying"

    log = _boot(stick, firmware=firmware, cdrom=False, where=tmp_path, name="-2")
    assert _image_kernel_line(_kernel_args(log), loader, "fallback"), log[-3000:]
    assert _grubenv(stick) == {"fr_os_state": "failed", "fr_os_staged": "6.1.0-99-amd64"}

    log = _boot(stick, firmware=firmware, cdrom=False, where=tmp_path, name="-3")
    assert _image_kernel_line(_kernel_args(log), loader, "image"), log[-3000:]
    assert _grubenv(stick)["fr_os_state"] == "failed"


@pytest.mark.parametrize("firmware", ["bios", "uefi"])
def test_a_confirmed_kernel_boots_by_default_and_every_boot_is_checked(iso, tmp_path, firmware):
    _needs(firmware)
    loader = "grub-pc" if firmware == "bios" else "grub-efi"
    stick = _staged_stick(iso, tmp_path, state="good")
    log = _boot(stick, firmware=firmware, cdrom=False, where=tmp_path)
    assert _staged_kernel_line(_kernel_args(log), loader, "staged"), log[-3000:]
    assert _grubenv(stick)["fr_os_state"] == "booting"  # until the router confirms this boot too


@pytest.mark.parametrize("firmware", ["bios", "uefi"])
def test_a_staged_kernel_whose_files_dont_match_their_hashes_is_never_booted(iso, tmp_path, firmware):
    _needs(firmware)
    loader = "grub-pc" if firmware == "bios" else "grub-efi"
    stick = _staged_stick(iso, tmp_path, damage=True)
    log = _boot(stick, firmware=firmware, cdrom=False, where=tmp_path)
    assert _image_kernel_line(_kernel_args(log), loader, "fallback"), log[-3000:]
    assert _grubenv(stick)["fr_os_state"] == "failed"
