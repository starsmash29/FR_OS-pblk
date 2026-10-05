"""A kernel staged on the persistence partition (ROADMAP SEC-14):
frfw.kernel_boot's side of it -- the GRUB environment block, staging,
and the check at the end of every boot GRUB started.

GRUB's side (the state machine in grub.cfg, run by real firmware) is
tests/test_boot_chain.py; the whole thing on the real image is boots 5-8
of installer/qemu-boot-test.py.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

import pytest

from frfw import cli, kernel_boot
from frfw.kernel_boot import BOOTING, FAILED, GOOD, STAGED, STATE, TRIAL, TRYING

KERNEL = b"\0" * 0x202 + b"HdrS" + b"k" * 8192
VERSION = "6.1.0-99-amd64"


@pytest.fixture
def files(tmp_path):
    (tmp_path / "vmlinuz").write_bytes(KERNEL)
    (tmp_path / "initrd.img").write_bytes(b"initrd" * 4096)
    root = tmp_path / "persistence"
    (root / "rw").mkdir(parents=True)
    return tmp_path / "vmlinuz", tmp_path / "initrd.img", root / kernel_boot.BOOT_DIR_NAME


def _env(boot_dir: Path) -> dict:
    return kernel_boot.read_env(boot_dir / kernel_boot.ENV_NAME)


def _set_state(boot_dir: Path, state: str) -> None:
    kernel_boot.write_env(boot_dir / kernel_boot.ENV_NAME, {STATE: state, STAGED: VERSION})


# -- the environment block ------------------------------------------------------------


def test_the_block_is_grubs_format():
    data = kernel_boot.format_env({STATE: TRIAL, STAGED: VERSION})
    assert len(data) == kernel_boot.ENV_SIZE
    assert data.startswith(b"# GRUB Environment Block\nfr_os_state=trial\nfr_os_staged=6.1.0-99-amd64\n#")
    assert kernel_boot.parse_env(data) == {STATE: TRIAL, STAGED: VERSION}


@pytest.mark.parametrize("data", [b"", b"x" * 1024, kernel_boot.format_env({})[:-1]])
def test_anything_else_reads_as_nothing_staged(data):
    assert kernel_boot.parse_env(data) == {}


@pytest.mark.parametrize("name,value", [("fr_os_state", "a\nb"), ("fr_os_state", "a b"), ("x=y", "1"),
                                        ("fr_os_staged", "\\")])
def test_nothing_that_could_break_the_block_is_written(name, value):
    with pytest.raises(kernel_boot.KernelBootError):
        kernel_boot.format_env({name: value})


@pytest.mark.skipif(shutil.which("grub-editenv") is None, reason="needs grub-editenv (grub-common)")
def test_grub_reads_what_the_router_writes_and_the_other_way_round(tmp_path):
    ours = tmp_path / "ours"
    kernel_boot.write_env(ours, {STATE: GOOD, STAGED: VERSION})
    listed = subprocess.run(["grub-editenv", str(ours), "list"], capture_output=True, text=True, check=True).stdout
    assert listed.splitlines() == ["fr_os_state=good", "fr_os_staged=6.1.0-99-amd64"]

    theirs = tmp_path / "theirs"
    subprocess.run(["grub-editenv", str(theirs), "create"], check=True)
    subprocess.run(["grub-editenv", str(theirs), "set", "fr_os_state=trying", f"fr_os_staged={VERSION}"], check=True)
    assert kernel_boot.read_env(theirs) == {STATE: TRYING, STAGED: VERSION}


def test_a_new_block_replaces_the_old_one_in_one_step(tmp_path):
    path = tmp_path / "grubenv"
    kernel_boot.write_env(path, {STATE: TRIAL})
    kernel_boot.write_env(path, {STATE: GOOD})
    assert kernel_boot.read_env(path) == {STATE: GOOD}
    assert sorted(p.name for p in tmp_path.iterdir()) == ["grubenv"]  # no temporary file left


# -- where it lives -----------------------------------------------------------------------


def test_the_persistence_filesystem_live_boot_mounted():
    mounts = ("/dev/sr0 /run/live/medium iso9660 ro 0 0\n"
              "/dev/loop0 /run/live/rootfs/filesystem.squashfs squashfs ro 0 0\n"
              "/dev/vda3 /run/live/persistence/vda3 ext4 rw,noatime 0 0\n"
              "overlay / overlay rw 0 0\n")
    assert kernel_boot.persistence_root(mounts) == Path("/run/live/persistence/vda3")
    assert kernel_boot.boot_dir(mounts) == Path("/run/live/persistence/vda3/fr_os-boot")
    assert kernel_boot.boot_dir("/dev/sda1 / ext4 rw 0 0\n") is None


@pytest.mark.parametrize("cmdline,mode", [
    ("boot=live persistence fr_os.loader=grub-pc fr_os.kernel=trial panic=10", "trial"),
    ("boot=live fr_os.kernel=fallback", "fallback"),
    ("boot=live persistence", None),
])
def test_what_grub_said_this_boot_is(cmdline, mode):
    assert kernel_boot.boot_mode(cmdline) == mode


# -- staging ------------------------------------------------------------------------------


def test_a_staged_kernel_waits_for_its_trial(files):
    kernel, initrd, boot_dir = files
    kernel_boot.stage(kernel, initrd, VERSION, boot_dir=boot_dir)
    assert _env(boot_dir) == {STATE: TRIAL, STAGED: VERSION}
    slot = boot_dir / kernel_boot.SLOT
    assert (slot / "vmlinuz").read_bytes() == KERNEL
    assert (slot / "initrd.img").read_bytes() == initrd.read_bytes()
    assert kernel_boot.files_intact(boot_dir)
    # GRUB's `hashsum --check` format.
    lines = (slot / "SHA256SUMS").read_text().splitlines()
    assert [line.split("  ")[1] for line in lines] == ["vmlinuz", "initrd.img"]
    assert not (boot_dir.parent / "rw" / "fr_os-boot").exists()  # outside the overlay
    assert boot_dir.stat().st_mode & 0o777 == 0o700


def test_staging_again_replaces_the_kernel_and_starts_a_new_trial(files):
    kernel, initrd, boot_dir = files
    kernel_boot.stage(kernel, initrd, VERSION, boot_dir=boot_dir)
    _set_state(boot_dir, GOOD)
    initrd.write_bytes(b"newer" * 100)
    kernel_boot.stage(kernel, initrd, "6.1.0-100-amd64", boot_dir=boot_dir)
    assert _env(boot_dir) == {STATE: TRIAL, STAGED: "6.1.0-100-amd64"}
    assert (boot_dir / "staged" / "initrd.img").read_bytes() == b"newer" * 100
    assert kernel_boot.files_intact(boot_dir)
    assert sorted(p.name for p in boot_dir.iterdir()) == ["grubenv", "staged"]


def test_a_copy_that_fails_halfway_leaves_nothing_staged(files, monkeypatch):
    kernel, initrd, boot_dir = files
    kernel_boot.stage(kernel, initrd, VERSION, boot_dir=boot_dir)
    _set_state(boot_dir, GOOD)
    real = kernel_boot._copy_synced

    def failing(source, target):
        if target.name == "initrd.img":
            raise OSError(28, "No space left on device")
        real(source, target)

    monkeypatch.setattr(kernel_boot, "_copy_synced", failing)
    with pytest.raises(OSError):
        kernel_boot.stage(kernel, initrd, "6.1.0-100-amd64", boot_dir=boot_dir)
    # Not the old kernel half-replaced, not the new one: GRUB boots the image's.
    assert _env(boot_dir) == {}


@pytest.mark.parametrize("what", ["not a kernel", "empty initrd", "bad version", "no persistence"])
def test_what_is_refused(files, what):
    kernel, initrd, boot_dir = files
    version = VERSION
    if what == "not a kernel":
        kernel.write_bytes(b"#!/bin/sh\n")
    elif what == "empty initrd":
        initrd.write_bytes(b"")
    elif what == "bad version":
        version = "6.1; rm -rf /"
    else:
        boot_dir = boot_dir.parent / "nowhere" / "fr_os-boot"
    with pytest.raises(kernel_boot.KernelBootError):
        kernel_boot.stage(kernel, initrd, version, boot_dir=boot_dir)
    assert not boot_dir.exists()


def test_it_refuses_to_fill_the_persistence_partition(files, monkeypatch):
    kernel, initrd, boot_dir = files
    monkeypatch.setattr(kernel_boot.shutil, "disk_usage", lambda path: shutil._ntuple_diskusage(1, 1, 2**20))
    with pytest.raises(kernel_boot.KernelBootError, match="MiB free"):
        kernel_boot.stage(kernel, initrd, VERSION, boot_dir=boot_dir)
    assert not boot_dir.exists()


def test_unstaging_goes_back_to_the_images_kernel(files):
    kernel, initrd, boot_dir = files
    assert not kernel_boot.unstage(boot_dir=boot_dir)
    kernel_boot.stage(kernel, initrd, VERSION, boot_dir=boot_dir)
    assert kernel_boot.unstage(boot_dir=boot_dir)
    assert _env(boot_dir) == {} and not (boot_dir / "staged").exists()


def test_damaged_files_are_reported(files):
    kernel, initrd, boot_dir = files
    kernel_boot.stage(kernel, initrd, VERSION, boot_dir=boot_dir)
    (boot_dir / "staged" / "initrd.img").write_bytes(b"damaged")
    state = kernel_boot.status(boot_dir_path=boot_dir, cmdline="boot=live")
    assert state.intact is False and "DON'T MATCH" in state.summary


@pytest.mark.parametrize("state,cmdline,words", [
    (None, "boot=live fr_os.kernel=image", "nothing staged"),
    (TRIAL, "boot=live fr_os.kernel=image", "tried at the next reboot"),
    (GOOD, "boot=live fr_os.kernel=staged", "the staged one"),
    (FAILED, "boot=live fr_os.kernel=fallback", "the staged kernel failed"),
])
def test_status_says_what_boots(files, state, cmdline, words):
    kernel, initrd, boot_dir = files
    if state:
        kernel_boot.stage(kernel, initrd, VERSION, boot_dir=boot_dir)
        _set_state(boot_dir, state)
    assert words in kernel_boot.status(boot_dir_path=boot_dir, cmdline=cmdline).summary


# -- the check at the end of the boot --------------------------------------------------------


def _confirm(boot_dir, mode, problems=()):
    calls = []

    def wait():
        calls.append(1)
        return list(problems)

    outcome = kernel_boot.confirm_boot(boot_dir_path=boot_dir, cmdline=f"boot=live fr_os.kernel={mode}", wait=wait)
    return outcome, calls


@pytest.mark.parametrize("mode,before", [("trial", TRYING), ("staged", BOOTING)])
def test_a_staged_kernel_the_router_came_up_on_is_kept(files, mode, before):
    kernel, initrd, boot_dir = files
    kernel_boot.stage(kernel, initrd, VERSION, boot_dir=boot_dir)
    _set_state(boot_dir, before)
    outcome, calls = _confirm(boot_dir, mode)
    assert calls and not outcome.alert and not outcome.reboot
    assert _env(boot_dir) == {STATE: GOOD, STAGED: VERSION}


def test_a_trial_the_router_did_not_come_up_on_reboots_into_the_images_kernel(files):
    kernel, initrd, boot_dir = files
    kernel_boot.stage(kernel, initrd, VERSION, boot_dir=boot_dir)
    _set_state(boot_dir, TRYING)
    outcome, _ = _confirm(boot_dir, "trial", ["the webUI does not answer"])
    assert outcome.reboot and "failed its trial boot (the webUI does not answer)" in outcome.alert
    # Left "trying": GRUB marks it failed and boots the image's kernel.
    assert _env(boot_dir)[STATE] == TRYING


def test_a_confirmed_kernel_that_comes_up_badly_stays_up_until_the_admin_reboots(files):
    kernel, initrd, boot_dir = files
    kernel_boot.stage(kernel, initrd, VERSION, boot_dir=boot_dir)
    _set_state(boot_dir, BOOTING)
    outcome, _ = _confirm(boot_dir, "staged", ["persistence is not active"])
    assert not outcome.reboot and "next boot uses the image's own kernel" in outcome.alert
    assert _env(boot_dir)[STATE] == BOOTING


def test_a_fallback_boot_is_a_security_alert(files):
    kernel, initrd, boot_dir = files
    kernel_boot.stage(kernel, initrd, VERSION, boot_dir=boot_dir)
    _set_state(boot_dir, FAILED)
    outcome, calls = _confirm(boot_dir, "fallback")
    assert not calls and not outcome.reboot
    assert f"kernel {VERSION} did not come up" in outcome.alert
    assert _env(boot_dir)[STATE] == FAILED


@pytest.mark.parametrize("before,after", [(TRYING, TRIAL), (BOOTING, GOOD)])
def test_the_images_kernel_picked_from_the_menu_is_not_a_failure(files, before, after):
    kernel, initrd, boot_dir = files
    kernel_boot.stage(kernel, initrd, VERSION, boot_dir=boot_dir)
    _set_state(boot_dir, before)
    outcome, calls = _confirm(boot_dir, "image")
    assert not calls and not outcome.alert and not outcome.reboot
    assert _env(boot_dir)[STATE] == after


def test_an_unexpected_state_is_left_alone(files):
    kernel, initrd, boot_dir = files
    kernel_boot.stage(kernel, initrd, VERSION, boot_dir=boot_dir)
    _set_state(boot_dir, FAILED)
    outcome, calls = _confirm(boot_dir, "trial")
    assert not calls and not outcome.reboot and _env(boot_dir)[STATE] == FAILED


def test_the_check_waits_for_the_router_until_its_deadline():
    now = [0.0]
    results = [["the webUI does not answer"], ["the webUI does not answer"], []]
    problems = kernel_boot.wait_healthy(lambda: results.pop(0), timeout=60, interval=5,
                                        clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s))
    assert problems == [] and now[0] == 10

    now[0] = 0.0
    problems = kernel_boot.wait_healthy(lambda: ["the firewall's ruleset is not loaded"], timeout=60, interval=5,
                                        clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s))
    assert problems == ["the firewall's ruleset is not loaded"] and now[0] == 60


# -- the CLI step the unit runs: it reboots for a failed trial only ----------------------------


@pytest.fixture
def cli_env(files, monkeypatch):
    kernel, initrd, boot_dir = files
    kernel_boot.stage(kernel, initrd, VERSION, boot_dir=boot_dir)
    monkeypatch.setattr(kernel_boot, "boot_dir", lambda mounts_text=None: boot_dir)
    runs, alerts = [], []
    monkeypatch.setattr(cli.subprocess, "run", lambda argv, **kw: runs.append(argv))
    monkeypatch.setattr(cli, "_console_alert", lambda message, **kw: alerts.append(message))
    return boot_dir, runs, alerts


def test_the_unit_reboots_after_a_failed_trial(cli_env, monkeypatch):
    boot_dir, runs, alerts = cli_env
    _set_state(boot_dir, TRYING)
    monkeypatch.setattr(kernel_boot, "_CMDLINE_PATH", _cmdline(boot_dir, "trial"))
    monkeypatch.setattr(kernel_boot, "wait_healthy", lambda: ["the webUI does not answer"])
    assert cli._cmd_kernel_confirm_boot(argparse.Namespace()) == 0
    assert runs == [["systemctl", "reboot"]] and len(alerts) == 1


def test_the_unit_never_reboots_on_a_bug(cli_env, monkeypatch):
    boot_dir, runs, alerts = cli_env

    def broken(**kwargs):
        raise RuntimeError("a bug")

    monkeypatch.setattr(kernel_boot, "confirm_boot", broken)
    assert cli._cmd_kernel_confirm_boot(argparse.Namespace()) == 0
    assert runs == [] and alerts == []


def test_the_unit_confirms_a_good_boot_without_rebooting(cli_env, monkeypatch):
    boot_dir, runs, alerts = cli_env
    _set_state(boot_dir, BOOTING)
    monkeypatch.setattr(kernel_boot, "_CMDLINE_PATH", _cmdline(boot_dir, "staged"))
    monkeypatch.setattr(kernel_boot, "wait_healthy", lambda: [])
    assert cli._cmd_kernel_confirm_boot(argparse.Namespace()) == 0
    assert runs == [] and alerts == [] and _env(boot_dir)[STATE] == GOOD


def _cmdline(boot_dir: Path, mode: str) -> Path:
    path = boot_dir.parent.parent / "cmdline"
    path.write_text(f"boot=live persistence fr_os.loader=grub-pc fr_os.kernel={mode}\n")
    return path
