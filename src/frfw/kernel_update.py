"""Debian's kernel fixes, prepared for a trial boot (ROADMAP SEC-14, step 3).

frfw.kernel_boot tries a staged kernel once and keeps it only when the
router comes up on it. This module gets the kernel to stage: once a day
(fr-kernel-prepare.timer, `update.kernel_updates`, on by default) it
asks apt which kernel Debian's `linux-image-amd64` points at now and, if
that is a newer ABI than every kernel the router has, installs it --
from the configured Debian archive, its Release signatures checked by apt
against debian-archive-keyring, the same chain as every other package.

Installed into the live system's persistent root, the package puts
`/boot/vmlinuz-<v>` and its modules (`/usr/lib/modules/<v>`) on the
persistence partition. Its initrd is *not* built on the router: an
initrd made by mkinitramfs inside the running live system lacked
libmount (copy_exec resolved libraries through live-boot's own mounts)
and the kernel panicked -- found by the boot test. Instead it is the
image's own initrd, the one the medium boots with, with its kernel
modules exchanged for the new kernel's: the same modules plus what they
depend on, `depmod` run for the new kernel. Nothing else in an initrd
(busybox, live-boot, the libraries) depends on the kernel version. The
archive is edited, not unpacked -- every other entry is copied byte for
byte, setuid `mount` and device nodes included -- and checked for
live-boot and the new kernel's modules before anything calls the kernel
ready.

It never stages and never reboots: the kernel is "ready to try". The
admin's "Try it" on the Update screen (the update-helper's `kernel_try`)
stages it and reboots into its trial -- the only reboot FR_OS asks for.
So a power cut boots the known kernel, not an untried one.

Unattended-upgrades keeps excluding the kernel (hooks/0050): only this
path installs one, and it removes again what it installed once a kernel
is neither prepared, staged, running nor the image's own. The image's
kernel package is never touched: its modules are what the fallback
boots with.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from frfw import kernel_boot, paths

META_PACKAGE = "linux-image-amd64"
PACKAGE_PREFIX = "linux-image-"
BOOT = Path("/boot")
#: Where live-boot mounted the image's root (the squashfs): its kernel's
#: modules are the image's own kernel.
IMAGE_ROOT = Path("/run/live/rootfs")
#: The image's own kernel on the boot medium, when /boot doesn't have it,
#: and the initrd every prepared kernel's is made from.
MEDIUM_KERNEL = Path("/run/live/medium/live/vmlinuz")
MEDIUM_INITRD = Path("/run/live/medium/live/initrd.img")
#: The installed kernels' modules (merged /usr).
MODULES_ROOT = Path("/usr/lib/modules")
#: Where the initrds it makes go (root's, on the persistence partition).
INITRD_DIR = Path("/var/lib/fr_os/kernels")
#: What must stay free on the persistence partition after a kernel is
#: installed, and what its initrd and staged copy take besides (review
#: v0.2.1 #1): a full partition would stop config saves and logging.
RESERVE_BYTES = 256 * 2**20
EXTRA_BYTES = 160 * 2**20
#: What depmod needs next to the modules.
_MODULE_INDEX = ("modules.order", "modules.builtin", "modules.builtin.modinfo")
_MODULE_SUFFIX = re.compile(r"\.ko(\.(xz|zst|gz))?\Z")

_ABI = re.compile(r"(\d+)\.(\d+)\.(\d+)-(\d+)-amd64\Z")

Runner = Callable[[list[str]], str]


class KernelUpdateError(Exception):
    """A kernel could not be prepared; what the message says was left."""


def _run(argv: list[str]) -> str:
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=1800)
    if proc.returncode != 0:
        raise KernelUpdateError(f"{' '.join(argv)} failed: {(proc.stderr or proc.stdout).strip()[-500:]}")
    return proc.stdout


def abi_key(version: str | None) -> tuple[int, ...] | None:
    """6.1.0-54-amd64 -> (6, 1, 0, 54); None for anything else."""
    match = _ABI.match(version or "")
    return tuple(int(part) for part in match.groups()) if match else None


def newer(version: str, than: str | None) -> bool:
    mine, theirs = abi_key(version), abi_key(than)
    return mine is not None and (theirs is None or mine > theirs)


def candidate(run: Runner = _run) -> str | None:
    """The kernel ABI Debian's linux-image-amd64 points at now (apt's
    candidate), e.g. 6.1.0-54-amd64."""
    record = run(["apt-cache", "show", "--no-all-versions", "--", META_PACKAGE])
    for line in record.splitlines():
        if line.startswith(("Depends:", "Pre-Depends:")):
            for found in re.findall(r"linux-image-(\S+?)(?:\s|,|$)", line):
                if abi_key(found):
                    return found
    return None


# -- what it remembers ------------------------------------------------------------


def load_state(path: Path = paths.KERNEL_UPDATE_STATE_PATH) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {"installed": []}
    if not isinstance(data, dict):
        return {"installed": []}
    data.setdefault("installed", [])
    return data


def save_state(state: dict, path: Path = paths.KERNEL_UPDATE_STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
    tmp.replace(path)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# -- preparing -------------------------------------------------------------------------


def image_kernels(image_root: Path = IMAGE_ROOT) -> set[str]:
    """The kernels whose modules are in the image itself (the squashfs)."""
    found = set()
    for modules in image_root.glob("*/usr/lib/modules/*"):
        if abi_key(modules.name):
            found.add(modules.name)
    return found


def _installed(package: str, run: Runner) -> bool:
    try:
        return run(["dpkg-query", "-W", "-f=${Status}", "--", package]).strip() == "install ok installed"
    except KernelUpdateError:
        return False


def installed_size(package: str, run: Runner = _run) -> int:
    """Bytes the package takes once installed (apt's Installed-Size, KiB)."""
    for line in run(["apt-cache", "show", "--no-all-versions", "--", package]).splitlines():
        if line.startswith("Installed-Size:"):
            return int(line.split(":", 1)[1].strip()) * 1024
    raise KernelUpdateError(f"apt gives no installed size for {package}")


def _check_room(package: str, where: Path, run: Runner) -> None:
    """Refuse an install that would leave the persistence partition with
    less than RESERVE_BYTES (review v0.2.1 #1)."""
    needed = installed_size(package, run) + EXTRA_BYTES + RESERVE_BYTES
    free = shutil.disk_usage(where).free
    if free < needed:
        raise KernelUpdateError(f"not enough room for {package}: {free // 2**20} MiB free on the persistence "
                                f"partition, {needed // 2**20} MiB needed (the kernel, its initrd and a reserve) "
                                "-- use a bigger stick, or turn kernel updates off")


class Outcome:
    def __init__(self, message: str, *, alert: str | None = None, ready: str | None = None) -> None:
        self.message, self.alert, self.ready = message, alert, ready


def prepare(*, version: str | None = None, enabled: bool = True, run: Runner = _run,
            state_path: Path = paths.KERNEL_UPDATE_STATE_PATH, boot_dir: Path | None = None,
            boot: Path = BOOT, running: str | None = None, image: set[str] | None = None,
            medium_kernel: Path = MEDIUM_KERNEL, medium_initrd: Path = MEDIUM_INITRD,
            modules_root: Path = MODULES_ROOT, initrd_dir: Path = INITRD_DIR) -> Outcome:
    """Get the kernel to try ready. `version`: that one (an admin's
    choice; also how the boot test prepares the running kernel without
    the network), else Debian's newest when it is newer than everything
    here. Raises KernelUpdateError when it can't."""
    running = running or os.uname().release
    image = image_kernels() if image is None else image
    state = load_state(state_path)
    staged = kernel_boot.status(boot_dir_path=boot_dir) if boot_dir is not None else None
    failed = staged.staged if staged and staged.state == kernel_boot.FAILED else None

    if version is None:
        if not enabled:
            return Outcome("kernel updates are off (update.kernel_updates)")
        run(["apt-get", "update", "-q"])
        version = candidate(run)
        if version is None:
            raise KernelUpdateError(f"apt names no kernel for {META_PACKAGE}")
        have = [running, (state.get("prepared") or {}).get("version")]
        if staged and staged.state in (kernel_boot.TRIAL, kernel_boot.TRYING, kernel_boot.GOOD, kernel_boot.BOOTING):
            have.append(staged.staged)
        newest = max((v for v in have if abi_key(v)), key=abi_key, default=None)
        if not newer(version, newest):
            return Outcome(f"no newer kernel: Debian's is {version}, this router has {newest}")
        if version == failed:
            return Outcome(f"kernel {version} failed its trial boot here; it is not prepared again")
    kernel_boot.check_version(version)

    package = PACKAGE_PREFIX + version
    if not _installed(package, run):
        _check_room(package, (boot_dir.parent if boot_dir is not None else Path("/")), run)
        run(["apt-get", "install", "-y", "-q", "--no-install-recommends",
             "-o", "Dpkg::Options::=--force-confold", "--", package])
        if package not in state["installed"]:
            state["installed"].append(package)
            save_state(state, state_path)

    kernel = boot / f"vmlinuz-{version}"
    if not kernel.is_file() and version in image and medium_kernel.is_file():
        kernel = medium_kernel  # the image's own, as the medium boots it
    if not kernel.is_file():
        raise KernelUpdateError(f"{package} is installed but {kernel} is not there")
    initrd = initrd_dir / f"initrd.img-{version}"
    build_initrd(medium_initrd, modules_root / version, version, initrd, run=run)

    state["prepared"] = {"version": version, "kernel": str(kernel), "initrd": str(initrd), "prepared_at": _now()}
    save_state(state, state_path)
    removed = clean_up(state, keep={version, running, *image, *([staged.staged] if staged and staged.staged
                                                                    and staged.state != kernel_boot.FAILED else [])},
                       run=run, state_path=state_path)
    note = f"; removed {', '.join(removed)}" if removed else ""
    return Outcome(f"kernel {version} is ready to try{note}", ready=version,
                   alert=f"kernel {version} is ready to try (Update screen: trying it reboots the router)")


# -- the initrd: the image's own, its kernel modules exchanged ----------------------------
#
# The archive is edited, never unpacked: unpacking it on the router would
# have to recreate its setuid `mount` (refused in fr-kernel-prepare's
# sandbox, RestrictSUIDSGID) and its device nodes. Every entry but the
# old kernel's modules is copied as it is, byte for byte.

_NEWC = b"070701"
_TRAILER = "TRAILER!!!"


def _pad4(n: int) -> int:
    return (4 - n % 4) % 4


class _Entry:
    __slots__ = ("raw", "name", "ino")

    def __init__(self, raw: bytes, name: str, ino: int) -> None:
        self.raw, self.name, self.ino = raw, name, ino


def _read_newc(data: bytes, offset: int = 0) -> tuple[list[_Entry], int]:
    """The entries of one newc cpio archive at `offset` (trailer left
    out), and where it ends."""
    entries = []
    while True:
        if data[offset:offset + 6] != _NEWC:
            raise KernelUpdateError(f"not a newc cpio archive at byte {offset}")
        fields = [int(data[offset + 6 + 8 * i:offset + 14 + 8 * i], 16) for i in range(13)]
        namesize, filesize = fields[11], fields[6]
        name_start = offset + 110
        name = data[name_start:name_start + namesize - 1].decode("utf-8", "surrogateescape")
        data_start = name_start + namesize + _pad4(110 + namesize)
        end = data_start + filesize + _pad4(filesize)
        if name == _TRAILER:
            return entries, end
        entries.append(_Entry(data[offset:end], name, fields[0]))
        offset = end


def _newc_entry(name: str, mode: int, data: bytes, ino: int, mtime: int) -> bytes:
    encoded = name.encode() + b"\0"
    header = _NEWC + b"".join(b"%08X" % v for v in (ino, mode, 0, 0, 2 if mode & 0o040000 else 1, mtime,
                                                     len(data), 0, 0, 0, 0, len(encoded), 0))
    return (header + encoded + b"\0" * _pad4(110 + len(encoded)) + data + b"\0" * _pad4(len(data)))


def _split_initrd(blob: bytes) -> tuple[bytes, bytes]:
    """(the uncompressed early archives, e.g. microcode, as they are; the
    main archive, decompressed)."""
    offset = 0
    while blob[offset:offset + 6] == _NEWC:
        _entries, offset = _read_newc(blob, offset)
        while offset < len(blob) and blob[offset] == 0:  # padding between archives
            offset += 1
    early, compressed = blob[:offset], blob[offset:]
    if compressed[:2] == b"\x1f\x8b":
        return early, gzip.decompress(compressed)
    if compressed[:6] == b"\xfd7zXZ\x00":
        import lzma

        return early, lzma.decompress(compressed)
    if compressed[:4] == b"\x28\xb5\x2f\xfd":
        proc = subprocess.run(["zstd", "-dc"], input=compressed, capture_output=True)
        if proc.returncode != 0:
            raise KernelUpdateError(f"zstd could not decompress the initrd: {proc.stderr.decode(errors='replace')}")
        return early, proc.stdout
    raise KernelUpdateError("the initrd's main archive is in a compression this router can't read")


def _bare(relative: str) -> str:
    return _MODULE_SUFFIX.sub("", relative)


def build_initrd(base: Path, modules: Path, version: str, out: Path, *, run: Runner = _run) -> None:
    """`base` (the image's initrd) with its kernel modules exchanged for
    the same ones -- and what they depend on -- from `modules`
    (/usr/lib/modules/<version>), written to `out`."""
    if not base.is_file():
        raise KernelUpdateError(f"no initrd to start from: {base}")
    if not (modules / "modules.dep").is_file():
        raise KernelUpdateError(f"no modules for kernel {version} in {modules}")
    early, main = _split_initrd(base.read_bytes())
    entries, _end = _read_newc(main)
    names = {e.name for e in entries}
    if "scripts/live" not in names:
        raise KernelUpdateError(f"{base} has no live-boot: no kernel could find the router's root with it")
    olds = {e.name.split("/")[3] for e in entries if e.name.startswith("usr/lib/modules/") and e.name.count("/") >= 3}
    if len(olds) != 1:
        raise KernelUpdateError(f"{base} has {len(olds)} kernels' modules, not one")
    old_prefix = f"usr/lib/modules/{olds.pop()}"
    wanted = {_bare(e.name[len(old_prefix) + 1:]) for e in entries
              if e.name.startswith(old_prefix + "/") and _MODULE_SUFFIX.search(e.name)}

    # The new kernel's module files and dependencies, by bare name.
    available, depends = {}, {}
    for line in (modules / "modules.dep").read_text().splitlines():
        if ":" not in line:
            continue
        module, deps = line.split(":", 1)
        available[_bare(module)] = module
        depends[_bare(module)] = [_bare(d) for d in deps.split()]
    chosen, todo = set(), [m for m in wanted if m in available]
    while todo:
        module = todo.pop()
        if module not in chosen:
            chosen.add(module)
            todo.extend(d for d in depends.get(module, ()) if d in available)

    with tempfile.TemporaryDirectory(prefix="fros-initrd-") as tmp:
        tree = Path(tmp) / "lib" / "modules" / version
        tree.mkdir(parents=True)
        for module in chosen:
            (tree / available[module]).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(modules / available[module], tree / available[module])
        for name in _MODULE_INDEX:
            if (modules / name).is_file():
                shutil.copyfile(modules / name, tree / name)
        run(["depmod", "-b", tmp, version])

        kept = [e for e in entries if e.name != old_prefix and not e.name.startswith(old_prefix + "/")]
        ino = max((e.ino for e in kept), default=0) + 1
        mtime = int(base.stat().st_mtime)
        added = []
        new_prefix = f"usr/lib/modules/{version}"
        present = {e.name for e in kept}
        for path in [tree, *sorted(tree.rglob("*"))]:
            name = new_prefix + ("" if path == tree else "/" + str(path.relative_to(tree)))
            if path.is_dir():
                added.append(_newc_entry(name, 0o040755, b"", ino, mtime))
            else:
                added.append(_newc_entry(name, 0o100644, path.read_bytes(), ino, mtime))
            ino += 1
        if "usr/lib/modules" not in present:
            added.insert(0, _newc_entry("usr/lib/modules", 0o040755, b"", ino, mtime))
        archive = b"".join(e.raw for e in kept) + b"".join(added) + _newc_entry(_TRAILER, 0, b"", 0, 0)

    out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp_out = out.with_name(f".{out.name}.tmp")
    tmp_out.write_bytes(early + gzip.compress(archive, compresslevel=6))
    tmp_out.replace(out)
    written = {e.name for e in _read_newc(_split_initrd(out.read_bytes())[1])[0]}
    if f"{new_prefix}/modules.dep" not in written or "scripts/live" not in written:
        raise KernelUpdateError(f"{out} came out without live-boot or the modules of kernel {version}")


def clean_up(state: dict, *, keep: set[str], run: Runner = _run,
             state_path: Path = paths.KERNEL_UPDATE_STATE_PATH) -> list[str]:
    """Purge the kernel packages this module installed that nothing needs
    any more -- never one it didn't install, so never the image's."""
    removed = []
    for package in list(state["installed"]):
        if package[len(PACKAGE_PREFIX):] in keep:
            continue
        run(["apt-get", "purge", "-y", "-q", "--", package])
        state["installed"].remove(package)
        removed.append(package)
    if removed:
        save_state(state, state_path)
    return removed


def record_check(message: str, *, error: bool = False, state_path: Path = paths.KERNEL_UPDATE_STATE_PATH) -> None:
    state = load_state(state_path)
    state["last_check"] = {"at": _now(), "message": message, "error": error}
    save_state(state, state_path)


# -- what the Update screen shows, and its "Try it" --------------------------------------


def overview(*, state_path: Path = paths.KERNEL_UPDATE_STATE_PATH, boot_dir: Path | None = None) -> dict:
    """For the webUI (through the update-helper): plain values only."""
    # No hashing of the staged files here (review v0.2.1 #4): GRUB checks
    # them at every boot, `firewall-cli kernel status` on request.
    status = kernel_boot.status(boot_dir_path=boot_dir, check_files=False) if boot_dir is not None \
        else kernel_boot.status(check_files=False)
    state = load_state(state_path)
    prepared = (state.get("prepared") or {}).get("version")
    busy = status.staged == prepared and status.state in (
        kernel_boot.TRIAL, kernel_boot.TRYING, kernel_boot.GOOD, kernel_boot.BOOTING, kernel_boot.FAILED)
    return {
        "available": status.available,
        "running": status.running,
        "boot": status.boot,
        "state": status.state,
        "staged": status.staged,
        "intact": status.intact,
        "summary": status.summary,
        "ready": prepared if prepared and not busy else None,
        "last_check": state.get("last_check"),
    }


def try_prepared(*, boot_dir: Path, state_path: Path = paths.KERNEL_UPDATE_STATE_PATH) -> str:
    """Stage the prepared kernel for a trial at the next boot; the caller
    reboots. Raises KernelUpdateError / KernelBootError."""
    prepared = load_state(state_path).get("prepared") or {}
    version = prepared.get("version")
    if not version:
        raise KernelUpdateError("no kernel is ready to try")
    status = kernel_boot.status(boot_dir_path=boot_dir)
    if status.staged == version and status.state == kernel_boot.FAILED:
        raise KernelUpdateError(f"kernel {version} already failed its trial boot here")
    kernel_boot.stage(Path(prepared["kernel"]), Path(prepared["initrd"]), version, boot_dir=boot_dir)
    return version
