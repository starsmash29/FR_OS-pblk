"""Keeping a live-booted FR_OS's state across reboots.

The FR_OS image is a Debian live system: without persistence everything
written after boot -- config.yaml, the admin password, enabled services,
SSH host keys, DHCP leases -- lives in RAM and is gone at the next boot
(and fr-first-boot runs again, with a new password). Debian's live-boot
has a standard answer: with `persistence` on the kernel command line it
looks for a filesystem labelled "persistence" holding a
`persistence.conf`, and overlays what that file lists onto the running
system. FR_OS persists the whole root (`/ union`), so a live-booted
router behaves like an installed one.

This module:

- reports the state (`status`): live or not, persistence active or not,
  which device;
- finds room for a persistence partition on the medium FR_OS booted from
  (the USB stick the ISO was written to has everything after the image
  unallocated) and creates it there (`auto`, run once early at boot by
  fr-persistence-setup.service, before fr-first-boot);
- turns a whole disk the operator names into a persistence disk
  (`create_on_disk`, for an internal SSD when the ISO boots from a
  read-only medium or a VM's virtual CD).

It never touches an existing partition: on the boot medium it only
appends a new partition in unallocated space after the last one, and
`create_on_disk` refuses a disk that has partitions unless told to wipe
it. Everything is done with util-linux/e2fsprogs tools (sfdisk, partx,
blkid, mkfs.ext4); the kernel only needs to re-read the new partition
(`partx --add`, which works while the stick's first partition is
mounted -- `blockdev --rereadpt` would fail as "busy").
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

LABEL = "persistence"
CONF_NAME = "persistence.conf"
#: Persist the whole root filesystem (live-boot's "full persistence").
CONF_CONTENT = "/ union\n"

#: Smallest partition worth creating: config, logs, leases and a couple of
#: update releases fit comfortably.
MIN_BYTES = 256 * 1024 * 1024
#: Partitions start on a 1 MiB boundary, as every modern tool does.
ALIGN_BYTES = 1024 * 1024

LIVE_MEDIUM_MOUNT = "/run/live/medium"
LIVE_PERSISTENCE_PREFIX = "/run/live/persistence/"

_CMDLINE_PATH = Path("/proc/cmdline")
_MOUNTS_PATH = Path("/proc/mounts")
_SYS_BLOCK = Path("/sys/class/block")


class PersistenceError(Exception):
    """A persistence partition could not be set up; nothing was changed
    unless the message says otherwise."""


@dataclass
class Status:
    live: bool
    active: bool
    requested: bool  # "persistence" on the kernel command line
    devices: list[str] = field(default_factory=list)  # persistence filesystems in use
    boot_device: str | None = None  # what /run/live/medium is mounted from
    labelled: list[str] = field(default_factory=list)  # filesystems labelled "persistence"

    @property
    def summary(self) -> str:
        if not self.live:
            return "installed system -- changes are kept on its own disk"
        if self.active:
            return f"live system with persistence on {', '.join(self.devices)} -- changes survive reboots"
        if self.labelled and not self.requested:
            return ("live system booted without the 'persistence' option -- "
                    f"{', '.join(self.labelled)} is not in use, changes are lost at reboot")
        return "live system without persistence -- changes are lost at reboot"


# -- reading the current state -------------------------------------------------


def _read(path: Path) -> str:
    try:
        return path.read_text()
    except OSError:
        return ""


def _mounts(mounts_text: str) -> list[tuple[str, str]]:
    result = []
    for line in mounts_text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            # /proc/mounts escapes spaces as \040
            result.append((parts[0], parts[1].replace("\\040", " ")))
    return result


def _run(cmd: list[str], *, input_text: str | None = None, check: bool = True) -> str:
    try:
        proc = subprocess.run(cmd, input=input_text, capture_output=True, text=True, timeout=120)
    except FileNotFoundError as exc:
        raise PersistenceError(f"{cmd[0]} is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise PersistenceError(f"{cmd[0]} timed out") from exc
    if check and proc.returncode != 0:
        raise PersistenceError(f"{' '.join(cmd)} failed: {(proc.stderr or proc.stdout).strip()}")
    return proc.stdout


def labelled_devices() -> list[str]:
    """Filesystems labelled "persistence" (blkid -L only returns one)."""
    try:
        out = _run(["blkid", "-t", f"LABEL={LABEL}", "-o", "device"], check=False)
    except PersistenceError:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def status(
    *,
    cmdline: str | None = None,
    mounts_text: str | None = None,
    labelled: list[str] | None = None,
) -> Status:
    cmdline = _read(_CMDLINE_PATH) if cmdline is None else cmdline
    mounts = _mounts(_read(_MOUNTS_PATH) if mounts_text is None else mounts_text)
    args = cmdline.split()
    live = "boot=live" in args
    devices = sorted({src for src, target in mounts if target.startswith(LIVE_PERSISTENCE_PREFIX)})
    boot_device = next((src for src, target in mounts if target == LIVE_MEDIUM_MOUNT), None)
    return Status(
        live=live,
        active=live and bool(devices),
        requested="persistence" in args,
        devices=devices,
        boot_device=boot_device,
        labelled=(labelled_devices() if labelled is None else labelled) if live else [],
    )


# -- block device helpers --------------------------------------------------------


def parent_disk(device: str, sys_block: Path = _SYS_BLOCK) -> str:
    """/dev/sda1 -> /dev/sda; a whole disk maps to itself."""
    name = Path(device).name
    node = sys_block / name
    if (node / "partition").exists():
        return "/dev/" + node.resolve().parent.name
    return device


def disk_is_suitable(disk: str, sys_block: Path = _SYS_BLOCK) -> str | None:
    """Why `disk` can't hold a persistence partition, or None if it can."""
    name = Path(disk).name
    if name.startswith(("sr", "loop", "ram", "zram")):
        return f"{disk} is a {'CD/DVD' if name.startswith('sr') else 'virtual'} device"
    node = sys_block / name
    if (node / "ro").exists() and _read(node / "ro").strip() == "1":
        return f"{disk} is read-only"
    return None


@dataclass
class FreeSpace:
    table: str  # "dos" or "gpt"
    start: int  # bytes, aligned
    size: int  # bytes
    sector_size: int
    last_partition: int


def free_space_after_last_partition(sfdisk_json: str, disk_bytes: int) -> FreeSpace:
    """Where a new partition fits at the end of the disk, from
    `sfdisk --json` output and the disk's size."""
    try:
        table = json.loads(sfdisk_json)["partitiontable"]
    except (ValueError, KeyError) as exc:
        raise PersistenceError("unreadable partition table") from exc
    label = table.get("label")
    if label not in ("dos", "gpt"):
        raise PersistenceError(f"unsupported partition table type {label!r}")
    sector = int(table.get("sectorsize", 512))
    partitions = table.get("partitions", [])
    end = max((p["start"] + p["size"] for p in partitions), default=0) * sector
    # GPT keeps a backup header in the last 33 sectors.
    usable_end = disk_bytes - (33 * sector if label == "gpt" else 0)
    start = -(-end // ALIGN_BYTES) * ALIGN_BYTES
    size = (usable_end - start) // ALIGN_BYTES * ALIGN_BYTES
    if label == "dos" and len(partitions) >= 4:
        raise PersistenceError("the MBR partition table already has four partitions")
    return FreeSpace(label, start, max(0, size), sector, len(partitions))


def _disk_bytes(disk: str) -> int:
    return int(_run(["blockdev", "--getsize64", disk]).strip())


def _partition_path(disk: str, number: int) -> str:
    # /dev/sda -> /dev/sda3, /dev/nvme0n1 or /dev/mmcblk0 -> ...p3
    return f"{disk}p{number}" if disk[-1].isdigit() else f"{disk}{number}"


def _make_filesystem(partition: str) -> None:
    _run(["mkfs.ext4", "-q", "-F", "-L", LABEL, partition])
    with tempfile.TemporaryDirectory(prefix="fros-persistence-") as mountpoint:
        _run(["mount", partition, mountpoint])
        try:
            Path(mountpoint, CONF_NAME).write_text(CONF_CONTENT)
        finally:
            _run(["umount", mountpoint], check=False)


# -- creating it -------------------------------------------------------------------


def create_on_boot_medium(disk: str, *, check_device: bool = True) -> str:
    """Append a persistence partition in the unallocated space at the end
    of `disk` (the medium FR_OS booted from). Returns the new partition.
    `check_device=False` skips the CD/loop/read-only refusal -- for tests
    on a loop device only."""
    reason = disk_is_suitable(disk) if check_device else None
    if reason:
        raise PersistenceError(reason)
    space = free_space_after_last_partition(_run(["sfdisk", "--json", disk]), _disk_bytes(disk))
    if space.size < MIN_BYTES:
        raise PersistenceError(
            f"only {space.size // 2**20} MiB free after the last partition on {disk} "
            f"(need {MIN_BYTES // 2**20} MiB) -- use a bigger stick or 'firewall-cli persistence create'"
        )
    part_type = "L" if space.table == "gpt" else "83"
    start_sector = space.start // space.sector_size
    _run(["sfdisk", "--append", "--no-reread", "--no-tell-kernel", disk],
         input_text=f"start={start_sector}, type={part_type}\n")
    number = space.last_partition + 1
    partition = _partition_path(disk, number)
    # Tell the kernel about the new partition without re-reading the whole
    # (busy) table.
    _run(["partx", "--add", "--nr", str(number), disk], check=False)
    if not Path(partition).exists():
        _run(["udevadm", "settle"], check=False)
    if not Path(partition).exists():
        raise PersistenceError(f"created partition {number} on {disk}, but {partition} did not appear")
    _make_filesystem(partition)
    return partition


def create_on_disk(disk: str, *, wipe: bool = False) -> str:
    """Make `disk` (a whole disk, e.g. an internal SSD) a persistence disk:
    one partition spanning it. Refuses a disk with partitions or mounted
    filesystems unless `wipe` is set (mounted ones are always refused)."""
    if parent_disk(disk) != disk:
        raise PersistenceError(f"{disk} is a partition; name the whole disk")
    reason = disk_is_suitable(disk)
    if reason:
        raise PersistenceError(reason)
    mounted = [src for src, _target in _mounts(_read(_MOUNTS_PATH))
               if src == disk or parent_disk(src) == disk]
    if mounted:
        raise PersistenceError(f"{disk} is in use ({', '.join(sorted(set(mounted)))} mounted)")
    existing = _run(["sfdisk", "--json", disk], check=False)
    if existing.strip() and json.loads(existing).get("partitiontable", {}).get("partitions") and not wipe:
        raise PersistenceError(f"{disk} already has partitions -- pass --wipe to erase everything on it")
    _run(["wipefs", "--all", "--quiet", disk])
    _run(["sfdisk", "--quiet", disk], input_text="label: gpt\n,,L\n")
    _run(["partx", "--update", disk], check=False)
    _run(["udevadm", "settle"], check=False)
    partition = _partition_path(disk, 1)
    if not Path(partition).exists():
        raise PersistenceError(f"{partition} did not appear after partitioning {disk}")
    _make_filesystem(partition)
    return partition


def auto(state: Status | None = None) -> tuple[str, str | None]:
    """The boot-time step: (outcome, device). Outcomes: "not-live",
    "active", "exists" (a labelled filesystem is there but wasn't used --
    booted without the option; nothing is created), "created" (reboot to
    use it), or "skipped: <reason>"."""
    state = state or status()
    if not state.live:
        return "not-live", None
    if state.active:
        return "active", state.devices[0]
    if state.labelled:
        return "exists", state.labelled[0]
    if not state.requested:
        return "skipped: booted without the 'persistence' option", None
    if not state.boot_device:
        return "skipped: the live medium is not mounted", None
    try:
        return "created", create_on_boot_medium(parent_disk(state.boot_device))
    except PersistenceError as exc:
        return f"skipped: {exc}", None
