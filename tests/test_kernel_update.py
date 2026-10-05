"""Debian's kernel fixes, prepared for a trial boot (ROADMAP SEC-14, step 3):
frfw.kernel_update, and the update-helper's kernel commands behind the
Update screen.

apt and dpkg are a fake here (`Apt`): it answers like them and records
what was asked. The real chain -- mkinitramfs with live-boot on the
router, the webUI's "Try", the trial -- is the boot test's boots 9-10.
"""

from __future__ import annotations

import os
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
    """apt-get/apt-cache/dpkg-query/mkinitramfs/lsinitramfs, faked."""

    def __init__(self, boot: Path, *, installed=(RUNNING,), show: str = SHOW, live_boot: bool = True) -> None:
        self.boot, self.installed, self.show, self.live_boot = boot, set(installed), show, live_boot
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> str:
        self.calls.append(argv)
        tool = argv[0]
        if tool == "apt-cache":
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
        elif tool == "mkinitramfs":
            Path(argv[2]).write_bytes(b"rebuilt initrd")
        elif tool == "lsinitramfs":
            return "init\nscripts/live\nscripts/live-bottom\n" if self.live_boot else "init\nscripts/local\n"
        return ""

    def asked(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if c[:len(prefix)] == list(prefix)]


@pytest.fixture
def router(tmp_path):
    boot = tmp_path / "boot"
    boot.mkdir()
    (boot / f"vmlinuz-{RUNNING}").write_bytes(KERNEL)
    persistence = tmp_path / "persistence"
    (persistence / "rw").mkdir(parents=True)
    return {"boot": boot, "boot_dir": persistence / kernel_boot.BOOT_DIR_NAME, "state": tmp_path / "kernel.json",
            "medium": tmp_path / "medium-vmlinuz"}


def _prepare(router, apt, **kwargs):
    return kernel_update.prepare(run=apt, state_path=router["state"], boot_dir=router["boot_dir"],
                                 boot=router["boot"], running=RUNNING, image={RUNNING},
                                 medium_kernel=router["medium"], **kwargs)


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


def test_an_initrd_without_live_boot_is_never_called_ready(router):
    apt = Apt(router["boot"], live_boot=False)
    with pytest.raises(KernelUpdateError, match="no live-boot"):
        _prepare(router, apt)
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
    assert apt.asked("mkinitramfs") == [["mkinitramfs", "-o", str(router["boot"] / f"initrd.img-{RUNNING}"),
                                         RUNNING]]
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


# -- the Update screen's view and its "Try" ---------------------------------------------------


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
