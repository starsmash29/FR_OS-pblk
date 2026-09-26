#!/usr/bin/env python3
"""Boot the FR_OS ISO in QEMU the way a user would, three times, and check
that it actually works and remembers what it was told.

    sudo installer/qemu-boot-test.py installer/live-build/binary.hybrid.iso

The ISO is written to a 2 GiB disk image (standing in for a USB stick)
attached to a VM with two NICs -- WAN on QEMU's user network, LAN on a
second one where the host reaches 192.168.1.1:443 through a port forward.

1. First boot: fr-persistence-setup finds the free space after the image,
   creates the persistence partition and reboots.
2. Second boot: persistence is active; fr-first-boot assigns the NICs,
   writes the config, generates the admin password and starts FR_OS; the
   webUI answers on the LAN. Then an ACPI power-off (the power button).
3. Third boot: first boot does not run again, the admin password from the
   second boot still works, a setting changed through the webUI is on the
   persistence partition afterwards.

Between boots the persistence partition is mounted on the host to read the
journal and files, so a failure says what went wrong. Needs root (losetup,
mount), qemu-system-x86_64 and curl. Takes a few minutes with KVM, ~15
without (TCG). Exit status 0 = every check passed.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path

WEBUI_PORT = 8443
DISK_SIZE = 2 * 2**30
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class Check:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def __call__(self, ok: bool, what: str) -> bool:
        print(f"  [{'PASS' if ok else 'FAIL'}] {what}", flush=True)
        if not ok:
            self.failures.append(what)
        return ok


class Vm:
    def __init__(self, workdir: Path, disk: Path, n: int, kvm: bool) -> None:
        self.serial = workdir / f"boot{n}.log"
        self.monitor = workdir / f"mon{n}.sock"
        cmd = [
            "qemu-system-x86_64", "-m", "2048", "-smp", "2", "-no-reboot",
            "-drive", f"file={disk},format=raw,if=virtio",
            "-nic", "user,model=virtio-net-pci,mac=52:54:00:00:00:01",
            "-nic", ("user,model=virtio-net-pci,mac=52:54:00:00:00:02,net=192.168.1.0/24,"
                     f"host=192.168.1.2,dhcpstart=192.168.1.50,hostfwd=tcp::{WEBUI_PORT}-192.168.1.1:443"),
            "-display", "none", "-serial", f"file:{self.serial}",
            "-monitor", f"unix:{self.monitor},server,nowait",
        ]
        if kvm:
            cmd[1:1] = ["-enable-kvm", "-cpu", "host"]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def log(self) -> str:
        try:
            return ANSI.sub("", self.serial.read_text(errors="replace"))
        except OSError:
            return ""

    def wait_exit(self, timeout: float) -> bool:
        try:
            self.proc.wait(timeout)
            return True
        except subprocess.TimeoutExpired:
            return False

    def monitor_command(self, command: str) -> None:
        with socket.socket(socket.AF_UNIX) as sock:
            sock.connect(str(self.monitor))
            time.sleep(0.3)
            sock.recv(65536)
            sock.sendall(command.encode() + b"\n")
            time.sleep(1)

    def power_off(self, timeout: float = 180) -> bool:
        self.monitor_command("system_powerdown")
        return self.wait_exit(timeout)

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()


@contextmanager
def persistence_partition(disk: Path):
    """Mount partition 3 (the persistence one) of the disk image read-only."""
    loop = subprocess.run(["losetup", "--find", "--show", str(disk)], check=True,
                          capture_output=True, text=True).stdout.strip()
    mountpoint = Path(tempfile.mkdtemp(prefix="fros-p3-"))
    try:
        # The hybrid ISO's partition 1 starts at sector 0; the kernel's
        # own scan skips partition 2, so add partition 3 explicitly.
        subprocess.run(["partx", "--add", "--nr", "3", loop], capture_output=True)
        subprocess.run(["mount", "-o", "ro", f"{loop}p3", str(mountpoint)], check=True)
        try:
            yield mountpoint / "rw"  # live-boot's overlay upper directory
        finally:
            subprocess.run(["umount", str(mountpoint)], check=False)
    finally:
        subprocess.run(["losetup", "--detach", loop], check=False)
        mountpoint.rmdir()


def journal(upper: Path, *args: str) -> str:
    return subprocess.run(
        ["journalctl", f"--directory={upper}/var/log/journal", "--no-pager", "-o", "cat", *args],
        capture_output=True, text=True,
    ).stdout


def webui_opener() -> urllib.request.OpenerDirector:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # the router's self-signed certificate
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
    )


def wait_for_webui(opener, timeout: float) -> str | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with opener.open(f"https://127.0.0.1:{WEBUI_PORT}/login", timeout=10) as resp:
                return resp.read().decode()
        except OSError:
            time.sleep(5)
    return None


def post(opener, path: str, fields: dict) -> str:
    data = urllib.parse.urlencode(fields).encode()
    with opener.open(f"https://127.0.0.1:{WEBUI_PORT}{path}", data=data, timeout=30) as resp:
        return resp.geturl()


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("iso", type=Path)
    parser.add_argument("--workdir", type=Path, help="keep the disk image and serial logs here")
    parser.add_argument("--kvm", action="store_true", help="use KVM (much faster) if /dev/kvm exists")
    args = parser.parse_args()
    if not shutil.which("qemu-system-x86_64"):
        print("qemu-system-x86_64 not found", file=sys.stderr)
        return 2

    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="fros-qemu-"))
    workdir.mkdir(parents=True, exist_ok=True)
    disk = workdir / "stick.img"
    shutil.copyfile(args.iso, disk)
    with disk.open("r+b") as fh:
        fh.truncate(DISK_SIZE)
    kvm = args.kvm and Path("/dev/kvm").exists()
    boot_timeout = 300 if kvm else 900
    check = Check()
    print(f"work directory: {workdir} ({'KVM' if kvm else 'TCG, slow'})")

    print("boot 1: persistence setup")
    vm = Vm(workdir, disk, 1, kvm)
    rebooted = vm.wait_exit(boot_timeout)
    vm.kill()
    log = vm.log()
    check("boot=live" in log and "persistence" in log.split("Command line:", 1)[-1].split("\n", 1)[0],
          "booted the normal menu entry with the persistence option")
    check("fr-persistence: created" in log, "created the persistence partition on the boot medium")
    check(rebooted, "rebooted by itself to start using it")

    print("boot 2: first boot")
    vm = Vm(workdir, disk, 2, kvm)
    opener = webui_opener()
    page = wait_for_webui(opener, boot_timeout)
    log = vm.log()
    check("fr-persistence: active" in log, "persistence active")
    check(page is not None and "Sign in" in page, "webUI answers on https://192.168.1.1/ from the LAN")
    check(vm.power_off(), "the power button shuts it down cleanly")
    vm.kill()
    with persistence_partition(disk) as upper:
        first_boot = journal(upper, "-u", "fr-first-boot.service")
        check("fr-first-boot: done" in first_boot, "fr-first-boot finished"
              + ("" if "did not start" not in first_boot else " (some units did not start)"))
        failed = sorted(set(re.findall(r"Failed to start (\S+)", journal(upper))))
        check(not failed, f"no unit failed to start{': ' + ', '.join(failed) if failed else ''}")
        issue = (upper / "etc" / "issue").read_text() if (upper / "etc" / "issue").exists() else ""
        match = re.search(r"login is 'admin' / '([^']+)'", issue)
        check(match is not None, "admin password shown on the console (/etc/issue)")
        password = match.group(1) if match else ""
        check((upper / "etc" / "fr_os" / "config.yaml").exists(), "config.yaml is on the persistence partition")

    print("boot 3: everything still there")
    vm = Vm(workdir, disk, 3, kvm)
    opener = webui_opener()
    page = wait_for_webui(opener, boot_timeout)
    check(page is not None, "webUI up again")
    landed = post(opener, "/login", {"username": "admin", "password": password}) if page else ""
    check(landed.endswith("/"), "the admin password from boot 2 still works")
    if landed.endswith("/"):
        post(opener, "/rules/timezone", {"timezone": "Europe/Budapest"})
    check(vm.power_off(), "powered off")
    vm.kill()
    with persistence_partition(disk) as upper:
        this_boot = journal(upper, "-b", "-u", "fr-first-boot.service")
        check("running initial setup" not in this_boot, "fr-first-boot did not run again")
        issue_now = (upper / "etc" / "issue").read_text()
        check(password and f"'{password}'" in issue_now and issue_now.count("initial webUI admin login") == 1,
              "no second password was generated")
        config = (upper / "etc" / "fr_os" / "config.yaml").read_text()
        check("Europe/Budapest" in config, "a change made in the webUI was saved to the persistence partition")

    print()
    if check.failures:
        print(f"{len(check.failures)} check(s) failed; logs in {workdir}")
        return 1
    print(f"all checks passed; logs in {workdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
