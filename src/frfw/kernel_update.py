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
persistence partition; `mkinitramfs` then builds `/boot/initrd.img-<v>`
with the image's live-boot hooks -- the modules are in the overlay when
that kernel boots. The initrd is checked for live-boot before anything
calls the kernel ready: without it the kernel could never find its root.

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

import json
import os
import re
import subprocess
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
#: The image's own kernel on the boot medium, when /boot doesn't have it.
MEDIUM_KERNEL = Path("/run/live/medium/live/vmlinuz")

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
            medium_kernel: Path = MEDIUM_KERNEL) -> Outcome:
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
    # mkinitramfs itself, not update-initramfs: on a live system live-tools
    # may divert that to a no-op ("disabled on read-only media") -- the
    # kernel package's own postinst then made no initrd either.
    initrd = boot / f"initrd.img-{version}"
    run(["mkinitramfs", "-o", str(initrd), version])
    if not initrd.is_file():
        raise KernelUpdateError(f"mkinitramfs made no {initrd}")
    if "scripts/live" not in run(["lsinitramfs", "--", str(initrd)]):
        raise KernelUpdateError(f"{initrd} has no live-boot: that kernel could not find the router's root")

    state["prepared"] = {"version": version, "kernel": str(kernel), "initrd": str(initrd), "prepared_at": _now()}
    save_state(state, state_path)
    removed = clean_up(state, keep={version, running, *image, *([staged.staged] if staged and staged.staged
                                                                    and staged.state != kernel_boot.FAILED else [])},
                       run=run, state_path=state_path)
    note = f"; removed {', '.join(removed)}" if removed else ""
    return Outcome(f"kernel {version} is ready to try{note}", ready=version,
                   alert=f"kernel {version} is ready to try (Update screen: trying it reboots the router)")


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
