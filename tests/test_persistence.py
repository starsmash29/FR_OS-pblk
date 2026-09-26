"""frfw.persistence: live-boot persistence status and partition setup."""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from frfw import persistence
from frfw.persistence import PersistenceError, Status, free_space_after_last_partition

LIVE_CMDLINE = "BOOT_IMAGE=/live/vmlinuz boot=live config persistence quiet"

# `sfdisk --json` of a real FR_OS hybrid ISO written to a stick: partition
# 1 spans the ISO image from sector 0, the EFI image (2) sits inside it.
HYBRID_ISO_TABLE = json.dumps({"partitiontable": {
    "label": "dos", "id": "0x017d4411", "device": "/dev/sdb", "unit": "sectors", "sectorsize": 512,
    "partitions": [
        {"node": "/dev/sdb1", "start": 0, "size": 671744, "type": "0", "bootable": True},
        {"node": "/dev/sdb2", "start": 180, "size": 20480, "type": "ef"},
    ],
}})


def test_status_installed_system():
    state = persistence.status(cmdline="root=/dev/sda2 ro", mounts_text="", labelled=[])
    assert not state.live and not state.active
    assert "installed" in state.summary


def test_status_live_without_persistence():
    mounts = "/dev/sdb1 /run/live/medium iso9660 ro 0 0\n"
    state = persistence.status(cmdline=LIVE_CMDLINE, mounts_text=mounts, labelled=[])
    assert state.live and state.requested and not state.active
    assert state.boot_device == "/dev/sdb1"
    assert "lost at reboot" in state.summary


def test_status_live_with_persistence():
    mounts = (
        "/dev/sdb1 /run/live/medium iso9660 ro 0 0\n"
        "/dev/sdb3 /run/live/persistence/sdb3 ext4 rw 0 0\n"
    )
    state = persistence.status(cmdline=LIVE_CMDLINE, mounts_text=mounts, labelled=["/dev/sdb3"])
    assert state.active and state.devices == ["/dev/sdb3"]
    assert "survive reboots" in state.summary


def test_status_labelled_but_booted_without_the_option():
    state = persistence.status(cmdline="boot=live config", mounts_text="", labelled=["/dev/sdb3"])
    assert not state.active and not state.requested
    assert "without the 'persistence' option" in state.summary


def test_free_space_on_a_hybrid_iso_stick():
    space = free_space_after_last_partition(HYBRID_ISO_TABLE, 8 * 2**30)
    assert space.table == "dos" and space.last_partition == 2
    assert space.start == 671744 * 512  # already on a 1 MiB boundary
    assert space.start % persistence.ALIGN_BYTES == 0
    assert space.size == 8 * 2**30 - space.start


def test_free_space_keeps_the_gpt_backup_header_free():
    table = json.dumps({"partitiontable": {"label": "gpt", "sectorsize": 512, "partitions": [
        {"start": 2048, "size": 2048},
    ]}})
    space = free_space_after_last_partition(table, 100 * 2**20)
    assert space.start == 2 * 2**20
    assert space.start + space.size <= 100 * 2**20 - 33 * 512


def test_a_full_mbr_table_is_refused():
    table = json.dumps({"partitiontable": {"label": "dos", "sectorsize": 512, "partitions": [
        {"start": 2048 * i, "size": 2048} for i in range(1, 5)
    ]}})
    with pytest.raises(PersistenceError, match="four partitions"):
        free_space_after_last_partition(table, 2**30)


def test_cd_and_loop_devices_are_not_suitable():
    assert "CD/DVD" in persistence.disk_is_suitable("/dev/sr0")
    assert "virtual" in persistence.disk_is_suitable("/dev/loop3")


def test_parent_disk(tmp_path):
    (tmp_path / "sda").mkdir()
    (tmp_path / "sda" / "sda1").mkdir()
    (tmp_path / "sda" / "sda1" / "partition").write_text("1")
    (tmp_path / "sda1").symlink_to(tmp_path / "sda" / "sda1")
    assert persistence.parent_disk("/dev/sda1", sys_block=tmp_path) == "/dev/sda"
    assert persistence.parent_disk("/dev/sda", sys_block=tmp_path) == "/dev/sda"


def _live(**kwargs) -> Status:
    base = dict(live=True, active=False, requested=True, devices=[], boot_device="/dev/sdb1", labelled=[])
    base.update(kwargs)
    return Status(**base)


def test_auto_decisions(monkeypatch):
    assert persistence.auto(_live(live=False))[0] == "not-live"
    assert persistence.auto(_live(active=True, devices=["/dev/sdb3"])) == ("active", "/dev/sdb3")
    # A labelled filesystem that wasn't used: never create a second one.
    assert persistence.auto(_live(labelled=["/dev/sdb3"])) == ("exists", "/dev/sdb3")
    assert persistence.auto(_live(requested=False))[0].startswith("skipped")
    assert persistence.auto(_live(boot_device=None))[0].startswith("skipped")

    created = []
    monkeypatch.setattr(persistence, "parent_disk", lambda dev: "/dev/sdb")
    monkeypatch.setattr(persistence, "create_on_boot_medium", lambda disk: created.append(disk) or "/dev/sdb3")
    assert persistence.auto(_live()) == ("created", "/dev/sdb3")
    assert created == ["/dev/sdb"]

    def fail(disk):
        raise PersistenceError("only 12 MiB free")
    monkeypatch.setattr(persistence, "create_on_boot_medium", fail)
    assert persistence.auto(_live()) == ("skipped: only 12 MiB free", None)


# -- the real thing, on a loop device ------------------------------------------------

needs_root_tools = pytest.mark.skipif(
    os.geteuid() != 0 or not all(shutil.which(t) for t in ("losetup", "sfdisk", "mkfs.ext4", "partx")),
    reason="needs root and util-linux/e2fsprogs to partition a loop device",
)


def _write_hybrid_iso_mbr(image: Path) -> None:
    """The MBR xorriso writes for the FR_OS hybrid ISO: partition 1 from
    sector 0 over the whole image, the EFI image (2) inside it. sfdisk
    refuses to create a partition at sector 0, so write it directly."""
    def entry(boot: int, ptype: int, start: int, size: int) -> bytes:
        return struct.pack("<B3sB3sII", boot, b"\xfe\xff\xff", ptype, b"\xfe\xff\xff", start, size)
    mbr = bytearray(512)
    mbr[440:444] = struct.pack("<I", 0x017D4411)
    mbr[446:462] = entry(0x80, 0x00, 0, 204800)
    mbr[462:478] = entry(0x00, 0xEF, 180, 20480)
    mbr[510:512] = b"\x55\xaa"
    with image.open("r+b") as fh:
        fh.write(mbr)


@needs_root_tools
def test_creates_a_persistence_partition_after_a_hybrid_iso_layout(tmp_path):
    image = tmp_path / "stick.img"
    with image.open("wb") as fh:
        fh.truncate(600 * 2**20)
    _write_hybrid_iso_mbr(image)
    loop = subprocess.run(["losetup", "--find", "--show", "--partscan", str(image)],
                          check=True, capture_output=True, text=True).stdout.strip()
    try:
        partition = persistence.create_on_boot_medium(loop, check_device=False)
        assert partition == f"{loop}p3"
        table = json.loads(subprocess.run(["sfdisk", "--json", loop], check=True,
                                          capture_output=True, text=True).stdout)["partitiontable"]
        starts = [(p["start"], p["size"]) for p in table["partitions"]]
        assert starts[:2] == [(0, 204800), (180, 20480)]  # untouched
        assert starts[2][0] == 204800 and starts[2][0] * 512 % persistence.ALIGN_BYTES == 0
        label = subprocess.run(["blkid", "-o", "value", "-s", "LABEL", partition],
                               capture_output=True, text=True).stdout.strip()
        assert label == persistence.LABEL
        mountpoint = tmp_path / "mnt"
        mountpoint.mkdir()
        subprocess.run(["mount", partition, str(mountpoint)], check=True)
        try:
            assert (mountpoint / "persistence.conf").read_text() == "/ union\n"
        finally:
            subprocess.run(["umount", str(mountpoint)], check=True)
        # Once there is no room left, it says so instead of guessing.
        with pytest.raises(PersistenceError, match="free after the last partition"):
            persistence.create_on_boot_medium(loop, check_device=False)
    finally:
        subprocess.run(["losetup", "--detach", loop], check=False)


@needs_root_tools
def test_create_on_disk_refuses_a_disk_with_partitions_unless_wiped(tmp_path, monkeypatch):
    image = tmp_path / "ssd.img"
    with image.open("wb") as fh:
        fh.truncate(300 * 2**20)
    subprocess.run(["sfdisk", "--quiet", str(image)], check=True, text=True, input="label: gpt\n,,L\n")
    loop = subprocess.run(["losetup", "--find", "--show", "--partscan", str(image)],
                          check=True, capture_output=True, text=True).stdout.strip()
    monkeypatch.setattr(persistence, "disk_is_suitable", lambda disk: None)  # it's a loop device
    try:
        with pytest.raises(PersistenceError, match="--wipe"):
            persistence.create_on_disk(loop)
        partition = persistence.create_on_disk(loop, wipe=True)
        assert partition == f"{loop}p1"
        label = subprocess.run(["blkid", "-o", "value", "-s", "LABEL", partition],
                               capture_output=True, text=True).stdout.strip()
        assert label == persistence.LABEL
        with pytest.raises(PersistenceError, match="is a partition"):
            persistence.create_on_disk(partition)
    finally:
        subprocess.run(["losetup", "--detach", loop], check=False)
