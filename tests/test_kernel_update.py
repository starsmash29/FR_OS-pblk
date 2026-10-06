"""Debian's kernel fixes, prepared for a trial boot (ROADMAP SEC-14, step 3):
frfw.kernel_update, and the update-helper's kernel commands behind the
Update screen.

apt and dpkg are a fake here (`Apt`): it answers like them and records
what was asked. The initrd is really built here, from a small initrd
made for the test with cpio (and checked with lsinitramfs/unmkinitramfs
where they exist). The real chain
-- the image's own initrd with the router's modules, the webUI's "Try",
the trial -- is the boot test's boots 9-10.
"""

from __future__ import annotations

import gzip
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from frfw import kernel_boot, kernel_update
from frfw.helper import update_client as client
from frfw.helper.peer import PeerPolicy
from frfw.helper.update_server import UpdateHelperServer
from frfw.kernel_update import KernelUpdateError

RUNNING = "6.1.0-53-amd64"
NEWER = "6.1.0-54-amd64"
KERNEL = b"\0" * 0x202 + b"HdrS" + b"k" * 1024

SHOW = f"""Package: linux-image-amd64
Source: linux-signed-amd64 (6.1.158+1)
Version: 6.1.158-1
Depends: linux-image-{NEWER} (= 6.1.158-1)
Description: Linux for 64-bit PCs (meta-package)
"""


class Apt:
    """apt-get/apt-cache/dpkg-query, faked."""

    def __init__(self, boot: Path, *, installed=(RUNNING,), show: str = SHOW, live_boot: bool = True) -> None:
        self.boot, self.installed, self.show, self.live_boot = boot, set(installed), show, live_boot
        self.installed_kib = 400 * 1024  # Debian's 6.1 kernel: about 400 MB of modules
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> str:
        self.calls.append(argv)
        tool = argv[0]
        if tool == "apt-cache":
            if argv[-1].startswith("linux-image-6"):  # a kernel package's own record
                return f"Package: {argv[-1]}\nInstalled-Size: {self.installed_kib}\n"
            return self.show
        if tool == "dpkg-query":
            version = argv[-1][len("linux-image-"):]
            if version in self.installed:
                return "install ok installed"
            raise KernelUpdateError("dpkg-query: no packages found")
        if tool == "apt-get" and argv[1] == "install":
            version = argv[-1][len("linux-image-"):]
            self.installed.add(version)
            (self.boot / f"vmlinuz-{version}").write_bytes(KERNEL)
            (self.boot / f"initrd.img-{version}").write_bytes(b"initrd from the postinst")
        elif tool == "apt-get" and argv[1] == "purge":
            version = argv[-1][len("linux-image-"):]
            self.installed.discard(version)
            (self.boot / f"vmlinuz-{version}").unlink(missing_ok=True)
        return ""

    def asked(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if c[:len(prefix)] == list(prefix)]


@pytest.fixture
def router(tmp_path, monkeypatch):
    built = []

    def fake_build(base, modules, version, out, *, run):
        built.append((base, modules, version))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(b"initrd for " + version.encode())

    monkeypatch.setattr(kernel_update, "build_initrd", fake_build)
    # A persistence partition with room (review v0.2.1 #1 has its own test).
    monkeypatch.setattr(kernel_update.shutil, "disk_usage", lambda path: shutil._ntuple_diskusage(8 << 30, 0, 8 << 30))
    boot = tmp_path / "boot"
    boot.mkdir()
    (boot / f"vmlinuz-{RUNNING}").write_bytes(KERNEL)
    persistence = tmp_path / "persistence"
    (persistence / "rw").mkdir(parents=True)
    return {"boot": boot, "boot_dir": persistence / kernel_boot.BOOT_DIR_NAME, "state": tmp_path / "kernel.json",
            "medium": tmp_path / "medium-vmlinuz", "initrds": tmp_path / "kernels", "built": built}


def _prepare(router, apt, **kwargs):
    return kernel_update.prepare(run=apt, state_path=router["state"], boot_dir=router["boot_dir"],
                                 boot=router["boot"], running=RUNNING, image={RUNNING},
                                 medium_kernel=router["medium"], medium_initrd=Path("/medium/initrd.img"),
                                 modules_root=Path("/modules"), initrd_dir=router["initrds"], **kwargs)


# -- which kernel ---------------------------------------------------------------------


def test_the_candidate_is_the_abi_debians_meta_package_points_at():
    assert kernel_update.candidate(lambda argv: SHOW) == NEWER
    assert kernel_update.candidate(lambda argv: "Package: linux-image-amd64\nDepends: foo\n") is None


@pytest.mark.parametrize("version,than,result", [
    ("6.1.0-54-amd64", "6.1.0-53-amd64", True),
    ("6.1.0-53-amd64", "6.1.0-53-amd64", False),
    ("6.1.0-9-amd64", "6.1.0-10-amd64", False),  # numbers, not strings
    ("6.12.0-1-amd64", "6.1.0-99-amd64", True),
    ("6.1.0-54-amd64", None, True),
    ("6.1.0-54-rt-amd64", "6.1.0-53-amd64", False),  # not this flavour
])
def test_newer_compares_the_abi_numerically(version, than, result):
    assert kernel_update.newer(version, than) is result


# -- preparing -------------------------------------------------------------------------


def test_a_newer_debian_kernel_is_installed_and_made_ready(router):
    apt = Apt(router["boot"])
    outcome = _prepare(router, apt)
    assert outcome.ready == NEWER and "ready to try" in outcome.alert
    assert apt.asked("apt-get", "update")
    assert apt.asked("apt-get", "install") == [["apt-get", "install", "-y", "-q", "--no-install-recommends",
                                                "-o", "Dpkg::Options::=--force-confold", "--",
                                                f"linux-image-{NEWER}"]]
    state = kernel_update.load_state(router["state"])
    assert state["installed"] == [f"linux-image-{NEWER}"]
    assert state["prepared"]["version"] == NEWER
    assert state["prepared"]["kernel"] == str(router["boot"] / f"vmlinuz-{NEWER}")
    # Nothing staged, nothing booted: that is the admin's "Try".
    assert not router["boot_dir"].exists()


def test_a_kernel_that_would_fill_the_persistence_partition_is_not_installed(router, monkeypatch):
    """Review v0.2.1 #1: a full partition stops config saves and logging."""
    free = 600 << 20  # 600 MiB: not enough for 400 MB + initrd + staged copy + the reserve
    monkeypatch.setattr(kernel_update.shutil, "disk_usage", lambda path: shutil._ntuple_diskusage(1 << 30, 0, free))
    apt = Apt(router["boot"])
    with pytest.raises(KernelUpdateError, match="not enough room for linux-image-6.1.0-54-amd64: 600 MiB free"):
        _prepare(router, apt)
    assert not apt.asked("apt-get", "install")


def test_nothing_is_done_when_the_router_has_that_kernel_already(router):
    apt = Apt(router["boot"], show=SHOW.replace(NEWER, RUNNING))
    outcome = _prepare(router, apt)
    assert outcome.ready is None and outcome.alert is None and "no newer kernel" in outcome.message
    assert not apt.asked("apt-get", "install")


def test_a_kernel_that_failed_its_trial_is_not_prepared_again(router):
    (router["boot"] / "vmlinuz-new").write_bytes(KERNEL)
    (router["boot"] / "initrd-new").write_bytes(b"x")
    kernel_boot.stage(router["boot"] / "vmlinuz-new", router["boot"] / "initrd-new", NEWER,
                      boot_dir=router["boot_dir"])
    kernel_boot.write_env(router["boot_dir"] / kernel_boot.ENV_NAME,
                          {kernel_boot.STATE: kernel_boot.FAILED, kernel_boot.STAGED: NEWER})
    apt = Apt(router["boot"])
    outcome = _prepare(router, apt)
    assert "failed its trial" in outcome.message and outcome.ready is None
    assert not apt.asked("apt-get", "install")


def test_switched_off_it_doesnt_even_ask_apt(router):
    apt = Apt(router["boot"])
    outcome = _prepare(router, apt, enabled=False)
    assert "off" in outcome.message and apt.calls == []


def test_the_initrd_is_made_from_the_images_own(router):
    apt = Apt(router["boot"])
    _prepare(router, apt)
    assert router["built"] == [(Path("/medium/initrd.img"), Path(f"/modules/{NEWER}"), NEWER)]
    assert kernel_update.load_state(router["state"])["prepared"]["initrd"] == str(
        router["initrds"] / f"initrd.img-{NEWER}")
    # Not mkinitramfs inside the live system: that initrd lacked libmount.
    assert not apt.asked("mkinitramfs") and not apt.asked("update-initramfs")


def test_a_kernel_whose_initrd_cant_be_made_is_never_called_ready(router, monkeypatch):
    def broken(*args, **kwargs):
        raise KernelUpdateError("no live-boot")

    monkeypatch.setattr(kernel_update, "build_initrd", broken)
    with pytest.raises(KernelUpdateError, match="no live-boot"):
        _prepare(router, Apt(router["boot"]))
    assert "prepared" not in kernel_update.load_state(router["state"])


def test_the_running_image_kernel_can_be_prepared_without_the_network(router):
    """--version of an installed kernel: no apt-get at all; the image's
    /boot may not have its vmlinuz -- the medium's is the same kernel."""
    (router["boot"] / f"vmlinuz-{RUNNING}").unlink()
    router["medium"].write_bytes(KERNEL)
    apt = Apt(router["boot"])
    outcome = _prepare(router, apt, version=RUNNING)
    assert outcome.ready == RUNNING
    assert not apt.asked("apt-get")
    assert router["built"][-1][2] == RUNNING
    state = kernel_update.load_state(router["state"])
    assert state["prepared"]["kernel"] == str(router["medium"]) and state["installed"] == []


def test_only_what_it_installed_is_removed_and_never_the_images_kernel(router):
    apt = Apt(router["boot"], installed={RUNNING, "6.1.0-50-amd64"})
    kernel_update.save_state({"installed": ["linux-image-6.1.0-51-amd64", "linux-image-6.1.0-52-amd64"]},
                             router["state"])
    _prepare(router, apt)
    purged = [c[-1] for c in apt.asked("apt-get", "purge")]
    # 51 and 52 were its own and nothing needs them; 50 isn't its own, and
    # the running (image) kernel is never touched.
    assert purged == ["linux-image-6.1.0-51-amd64", "linux-image-6.1.0-52-amd64"]
    assert kernel_update.load_state(router["state"])["installed"] == [f"linux-image-{NEWER}"]


def test_a_staged_kernel_is_kept_too(router):
    staged = "6.1.0-52-amd64"
    (router["boot"] / "v").write_bytes(KERNEL)
    (router["boot"] / "i").write_bytes(b"x")
    kernel_boot.stage(router["boot"] / "v", router["boot"] / "i", staged, boot_dir=router["boot_dir"])
    kernel_boot.write_env(router["boot_dir"] / kernel_boot.ENV_NAME,
                          {kernel_boot.STATE: kernel_boot.GOOD, kernel_boot.STAGED: staged})
    kernel_update.save_state({"installed": [f"linux-image-{staged}"]}, router["state"])
    apt = Apt(router["boot"])
    _prepare(router, apt)
    assert not apt.asked("apt-get", "purge")


def test_the_state_file_is_roots_alone(router):
    _prepare(router, Apt(router["boot"]))
    assert router["state"].stat().st_mode & 0o777 == 0o600


# -- the initrd: the image's own, with the new kernel's modules -----------------------------

OLD, NEW = "6.1.0-53-amd64", "6.1.0-54-amd64"
needs_initramfs_tools = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("unmkinitramfs", "lsinitramfs", "cpio")),
    reason="needs initramfs-tools and cpio",
)


def _pack(root: Path) -> bytes:
    names = ["."] + sorted(str(p.relative_to(root)) for p in root.rglob("*"))
    return subprocess.run(["cpio", "--quiet", "-o", "-H", "newc"], cwd=root, input="\n".join(names).encode(),
                          capture_output=True, check=True).stdout


def _tree(root: Path, files: dict[str, bytes]) -> Path:
    for name, data in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    return root


@pytest.fixture
def initrd_parts(tmp_path):
    """An initrd like the image's (live-boot, merged /usr, the old
    kernel's modules), and the new kernel's module tree."""
    main = _tree(tmp_path / "main", {
        "init": b"#!/bin/sh\n",
        "scripts/live": b"live-boot\n",
        "usr/lib/x86_64-linux-gnu/libmount.so.1": b"libmount",
        f"usr/lib/modules/{OLD}/kernel/drivers/net/virtio_net.ko": b"old virtio_net",
        f"usr/lib/modules/{OLD}/kernel/fs/squashfs/squashfs.ko": b"old squashfs",
        f"usr/lib/modules/{OLD}/modules.dep": b"old",
    })
    (main / "lib").symlink_to("usr/lib")
    # What the image's initrd really has and the router must not unpack:
    # a setuid binary (RestrictSUIDSGID in fr-kernel-prepare's sandbox).
    _tree(main, {"usr/bin/mount": b"\x7fELF mount"})
    os.chmod(main / "usr/bin/mount", 0o4755)
    modules = _tree(tmp_path / "modules" / NEW, {
        "kernel/drivers/net/virtio_net.ko": b"new virtio_net",
        "kernel/drivers/net/net_failover.ko": b"new net_failover",
        "kernel/fs/squashfs/squashfs.ko.xz": b"new squashfs, compressed",
        "kernel/sound/unrelated.ko": b"not in the image's initrd",
        "modules.order": b"order", "modules.builtin": b"builtin",
        "modules.dep": ("kernel/drivers/net/virtio_net.ko: kernel/drivers/net/net_failover.ko\n"
                        "kernel/drivers/net/net_failover.ko:\n"
                        "kernel/fs/squashfs/squashfs.ko.xz:\n"
                        "kernel/sound/unrelated.ko:\n").encode(),
    })
    return tmp_path, main, modules


def _depmod_then_list(calls):
    def run(argv):
        calls.append(argv)
        assert argv[0] == "depmod"  # nothing else runs: the archive is edited in Python
        Path(argv[2], "lib", "modules", argv[3], "modules.dep").write_text("generated\n")
        return ""
    return run


def _entries(initrd: Path) -> dict[str, int]:
    """name -> mode of the main archive's entries (frfw's own reader)."""
    _early, main = kernel_update._split_initrd(initrd.read_bytes())
    return {e.name: int(e.raw[14:22], 16) for e in kernel_update._read_newc(main)[0]}


@needs_initramfs_tools
def test_the_new_initrd_has_the_same_modules_from_the_new_kernel(initrd_parts):
    tmp, main, modules = initrd_parts
    base = tmp / "initrd.img"
    base.write_bytes(gzip.compress(_pack(main)))
    out, calls = tmp / "out" / f"initrd.img-{NEW}", []
    kernel_update.build_initrd(base, modules, NEW, out, run=_depmod_then_list(calls))
    listing = subprocess.run(["lsinitramfs", str(out)], capture_output=True, text=True, check=True).stdout.split()
    new = f"usr/lib/modules/{NEW}/kernel"
    assert {f"{new}/drivers/net/virtio_net.ko", f"{new}/drivers/net/net_failover.ko",  # its dependency
            f"{new}/fs/squashfs/squashfs.ko.xz"} <= set(listing)
    assert f"{new}/sound/unrelated.ko" not in listing  # only what the image's initrd had
    assert not any(path.startswith(f"usr/lib/modules/{OLD}") for path in listing)
    # Everything else is the image's, untouched: live-boot, the libraries.
    assert {"scripts/live", "usr/lib/x86_64-linux-gnu/libmount.so.1", f"usr/lib/modules/{NEW}/modules.order"} <= set(listing)
    assert ["depmod", "-b"] == calls[0][:2] and calls[0][3] == NEW
    # Copied, not unpacked: the setuid bit is still there.
    assert _entries(out)["usr/bin/mount"] == 0o104755


@needs_initramfs_tools
def test_an_early_microcode_archive_is_kept_in_front(initrd_parts):
    tmp, main, modules = initrd_parts
    early = _tree(tmp / "early", {"kernel/x86/microcode/AuthenticAMD.bin": b"microcode"})
    base = tmp / "initrd.img"
    base.write_bytes(_pack(early) + gzip.compress(_pack(main)))
    out = tmp / "out" / f"initrd.img-{NEW}"
    kernel_update.build_initrd(base, modules, NEW, out, run=_depmod_then_list([]))
    data = out.read_bytes()
    # Uncompressed and first, as the kernel wants it; then the main archive, compressed.
    assert data.startswith(b"070701") and b"kernel/x86/microcode/AuthenticAMD.bin" in data[:data.index(b"\x1f\x8b")]
    unpacked = tmp / "check"
    subprocess.run(["unmkinitramfs", str(out), str(unpacked)], check=True, capture_output=True)
    assert (unpacked / "early" / "kernel/x86/microcode/AuthenticAMD.bin").read_bytes() == b"microcode"
    assert (unpacked / "main" / f"usr/lib/modules/{NEW}/kernel/drivers/net/virtio_net.ko").read_bytes() == b"new virtio_net"


@needs_initramfs_tools
def test_an_initrd_without_live_boot_is_refused(initrd_parts):
    tmp, main, modules = initrd_parts
    (main / "scripts" / "live").unlink()
    base = tmp / "initrd.img"
    base.write_bytes(gzip.compress(_pack(main)))
    with pytest.raises(KernelUpdateError, match="no live-boot"):
        kernel_update.build_initrd(base, modules, NEW, tmp / "out" / "initrd", run=_depmod_then_list([]))
    assert not (tmp / "out" / "initrd").exists()


@needs_initramfs_tools
def test_a_zstd_initrd_is_read_too(initrd_parts):
    """Debian 12's mkinitramfs compresses with zstd when it can."""
    if not shutil.which("zstd"):
        pytest.skip("needs zstd")
    tmp, main, modules = initrd_parts
    base = tmp / "initrd.img"
    base.write_bytes(subprocess.run(["zstd", "-q", "-c"], input=_pack(main), capture_output=True,
                                    check=True).stdout)
    out = tmp / "out" / f"initrd.img-{NEW}"
    kernel_update.build_initrd(base, modules, NEW, out, run=_depmod_then_list([]))
    assert f"usr/lib/modules/{NEW}/modules.dep" in _entries(out)


def test_no_modules_for_the_kernel_no_initrd(tmp_path):
    (tmp_path / "initrd.img").write_bytes(b"x")
    with pytest.raises(KernelUpdateError, match="no modules"):
        kernel_update.build_initrd(tmp_path / "initrd.img", tmp_path / "nothing", NEW, tmp_path / "out")


# -- the Update screen's view and its "Try" ---------------------------------------------------


def test_the_update_screen_does_not_hash_the_staged_files(router, monkeypatch):
    """Review v0.2.1 #4: GRUB checks them at every boot; the page doesn't."""
    _prepare(router, Apt(router["boot"]))
    kernel_update.try_prepared(boot_dir=router["boot_dir"], state_path=router["state"])

    def no(*args, **kwargs):
        raise AssertionError("hashed the staged kernel")

    monkeypatch.setattr(kernel_boot, "files_intact", no)
    assert kernel_update.overview(state_path=router["state"], boot_dir=router["boot_dir"])["state"] == "trial"


def test_try_stages_the_prepared_kernel_for_its_trial(router):
    _prepare(router, Apt(router["boot"]))
    assert kernel_update.overview(state_path=router["state"], boot_dir=router["boot_dir"])["ready"] == NEWER
    assert kernel_update.try_prepared(boot_dir=router["boot_dir"], state_path=router["state"]) == NEWER
    env = kernel_boot.read_env(router["boot_dir"] / kernel_boot.ENV_NAME)
    assert env == {kernel_boot.STATE: kernel_boot.TRIAL, kernel_boot.STAGED: NEWER}
    view = kernel_update.overview(state_path=router["state"], boot_dir=router["boot_dir"])
    assert view["ready"] is None and view["state"] == "trial"  # no second "Try" button


def test_try_refuses_without_a_prepared_kernel_and_after_a_failed_trial(router):
    with pytest.raises(KernelUpdateError, match="no kernel is ready"):
        kernel_update.try_prepared(boot_dir=router["boot_dir"], state_path=router["state"])
    _prepare(router, Apt(router["boot"]))
    kernel_update.try_prepared(boot_dir=router["boot_dir"], state_path=router["state"])
    kernel_boot.write_env(router["boot_dir"] / kernel_boot.ENV_NAME,
                          {kernel_boot.STATE: kernel_boot.FAILED, kernel_boot.STAGED: NEWER})
    with pytest.raises(KernelUpdateError, match="already failed"):
        kernel_update.try_prepared(boot_dir=router["boot_dir"], state_path=router["state"])


# -- the update-helper's kernel commands ----------------------------------------------------------


@pytest.fixture
def helper(router, tmp_path):
    events = {"units": [], "reboots": 0, "alerts": []}
    _prepare(router, Apt(router["boot"]))

    def serve(policy=None):
        server = UpdateHelperServer(
            tmp_path / "update.sock", repo="x/y", state_path=tmp_path / "update_state.json",
            releases_dir=tmp_path / "releases", peer_policy=policy,
            kernel_state_path=router["state"], kernel_boot_dir=lambda: router["boot_dir"],
            start_unit=events["units"].append,
            reboot_soon=lambda: events.__setitem__("reboots", events["reboots"] + 1),
            alert=events["alerts"].append,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        return tmp_path / "update.sock"

    servers = []
    yield serve, events
    for server, thread in servers:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_the_helper_reports_the_kernel(helper):
    serve, _ = helper
    reply = client.kernel("kernel_status", serve())
    assert reply["ok"] and reply["kernel"]["ready"] == NEWER and reply["kernel"]["available"]


def test_try_from_the_webui_stages_alerts_and_reboots(helper, router):
    serve, events = helper
    reply = client.kernel("kernel_try", serve())
    assert reply["ok"] and NEWER in reply["message"]
    assert events["reboots"] == 1 and len(events["alerts"]) == 1 and NEWER in events["alerts"][0]
    assert kernel_boot.read_env(router["boot_dir"] / kernel_boot.ENV_NAME)[kernel_boot.STATE] == "trial"


def test_check_now_starts_the_prepare_unit_and_nothing_else(helper):
    serve, events = helper
    assert client.kernel("kernel_check", serve())["ok"]
    assert events["units"] == ["fr-kernel-prepare.service"] and events["reboots"] == 0


def test_cancel_goes_back_to_the_images_kernel(helper, router):
    serve, events = helper
    socket_path = serve()
    client.kernel("kernel_try", socket_path)
    assert client.kernel("kernel_cancel", socket_path)["ok"]
    assert kernel_boot.read_env(router["boot_dir"] / kernel_boot.ENV_NAME) == {}
    assert len(events["alerts"]) == 2


def test_a_failed_try_is_reported_and_never_reboots(helper, router):
    serve, events = helper
    kernel_update.save_state({"installed": []}, router["state"])  # nothing prepared
    reply = client.kernel("kernel_try", serve())
    assert not reply["ok"] and "no kernel is ready" in reply["message"]
    assert events["reboots"] == 0 and events["alerts"] == []


def test_a_parser_daemons_account_cant_try_a_kernel(helper):
    """frfw.helper.peer: the update-helper serves the full role only."""
    serve, events = helper
    sensor = PeerPolicy(full_uids=frozenset(), sensor_uids=frozenset({os.geteuid()}))
    reply = client.kernel("kernel_try", serve(sensor))
    assert not reply["ok"] and "may not use the update-helper" in reply["message"]
    assert events["reboots"] == 0
