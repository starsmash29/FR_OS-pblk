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
(busybox, live-boot, the libraries) depends on the kernel version. It is
checked for live-boot and the new kernel's modules before anything calls
the kernel ready.

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


def _archives(unpacked: Path) -> tuple[list[Path], Path]:
    """unmkinitramfs's output: early (uncompressed, e.g. microcode)
    archives and the main one, or just the main one."""
    if (unpacked / "main").is_dir():
        return sorted(p for p in unpacked.iterdir() if p.name.startswith("early")), unpacked / "main"
    return [], unpacked


def _cpio(root: Path) -> bytes:
    names = ["."] + sorted(str(p.relative_to(root)) for p in root.rglob("*"))
    proc = subprocess.run(["cpio", "--quiet", "-o", "-H", "newc"], cwd=root, input="\n".join(names).encode(),
                          capture_output=True)
    if proc.returncode != 0:
        raise KernelUpdateError(f"cpio failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


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
    with tempfile.TemporaryDirectory(prefix="fros-initrd-") as tmp:
        unpacked = Path(tmp) / "unpacked"
        proc = subprocess.run(["unmkinitramfs", str(base), str(unpacked)], capture_output=True, text=True)
        if proc.returncode != 0:
            raise KernelUpdateError(f"unmkinitramfs {base} failed: {proc.stderr.strip()}")
        early, main = _archives(unpacked)
        module_dirs = [d for d in (main / "usr" / "lib" / "modules").glob("*") if d.is_dir() and not d.is_symlink()]
        if len(module_dirs) != 1:
            raise KernelUpdateError(f"{base} has {len(module_dirs)} kernels' modules, not one")
        old = module_dirs[0]
        wanted = {_bare(str(p.relative_to(old))) for p in old.rglob("*.ko*") if _MODULE_SUFFIX.search(p.name)}

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

        shutil.rmtree(old)
        new = main / "usr" / "lib" / "modules" / version
        new.mkdir(parents=True)
        for module in chosen:
            target = new / available[module]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(modules / available[module], target)
        for name in _MODULE_INDEX:
            if (modules / name).is_file():
                shutil.copy2(modules / name, new / name)
        run(["depmod", "-b", str(main), version])

        out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp_out = out.with_name(f".{out.name}.tmp")
        with tmp_out.open("wb") as fh:
            for archive in early:
                fh.write(_cpio(archive))
            fh.write(gzip.compress(_cpio(main), compresslevel=6))
        tmp_out.replace(out)

    listing = run(["lsinitramfs", "--", str(out)])
    if "scripts/live" not in listing:
        raise KernelUpdateError(f"{out} has no live-boot: that kernel could not find the router's root")
    if f"usr/lib/modules/{version}/modules.dep" not in listing:
        raise KernelUpdateError(f"{out} has no modules for kernel {version}")


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
    status = kernel_boot.status(boot_dir_path=boot_dir) if boot_dir is not None else kernel_boot.status()
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
