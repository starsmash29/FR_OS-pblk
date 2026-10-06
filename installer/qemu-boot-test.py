#!/usr/bin/env python3
"""Boot the FR_OS ISO in QEMU the way a user would, ten times, and check
that it actually works and remembers what it was told.

    sudo installer/qemu-boot-test.py installer/live-build/binary.hybrid.iso

The ISO is written to a 2 GiB disk image (standing in for a USB stick)
attached to a VM with two NICs -- WAN on QEMU's user network, which has a
DHCP server like an upstream modem, and LAN on a tap device on the host
(192.168.1.2/24), which has none, like a laptop. First boot has to tell
them apart by that (ROADMAP SEC-8); the host reaches the webUI at
https://192.168.1.1/ over the tap, as a LAN client does.

1. First boot: fr-persistence-setup finds the free space after the image,
   creates the persistence partition and reboots.
2. Second boot: persistence is active; fr-first-boot assigns the NICs,
   writes the config, generates the admin password and starts FR_OS; the
   webUI answers on the LAN. Then an ACPI power-off (the power button).
3. Third boot: first boot does not run again, the admin password from the
   second boot still works, a setting changed through the webUI is on the
   persistence partition afterwards. The first sign-in goes through
   first-run setup (own username and password), after which the generated
   password is gone from the console. The Apply of the webUI's changes
   is held until it is confirmed, and is confirmed from the dashboard
   (ROADMAP SEC-26); it doesn't move the webUI -- turning the VPN on
   included -- and a LAN address change that would is refused: the
   admin's webUI address setting puts it on the VPN's address too
   (SEC-27). A move nobody confirms -- the webUI on the VPN alone -- goes
   back by itself at the deadline. At its end a config
   is saved that names a device the VM doesn't have; its apply changes
   nothing.
4. Fourth boot: config.yaml can't be applied (that device), so the router
   comes up with the config last applied in full, says so, raises a
   security alert, and the webUI is reachable (ROADMAP SEC-5).
5. Fifth to eighth boot: a kernel staged on the persistence partition
   (ROADMAP SEC-14) -- the image's own, copied there by
   frfw.kernel_boot.stage() from the host, as the router would. Boot 5
   tries it and keeps it (the router came up on it); the hardware
   watchdog (QEMU's i6300esb) is in use. Boot 6 tries it again with the
   webUI masked: the check at the end of the boot fails, and the router
   reboots by itself into ... boot 7, the image's own kernel, which
   raises a security alert. Boot 8 tries one whose initrd is broken: the
   kernel panics and reboots (panic=10), and GRUB has recorded the try.
6. Ninth and tenth boot: the Update screen's kernel card (ROADMAP SEC-14,
   step 3). "Check now" runs fr-kernel-prepare on the router -- pointed
   at the running kernel by a drop-in, so no Debian download is needed:
   the router makes the initrd from the image's own -- and the
   kernel is "ready to try"; "Try it" reboots the router into its trial,
   and boot 10 comes up on the router-built initrd and confirms it.

With --uefi the VM boots with UEFI firmware (OVMF, the `ovmf` package)
instead of BIOS; the CI runs the test both ways. Either way the kernel has
to come from GRUB's menu -- isolinux's default entry starts GRUB on BIOS
(ROADMAP SEC-14) -- which the first boot checks in the kernel command line.

Between boots the persistence partition is mounted on the host to read the
journal and files, so a failure says what went wrong. Needs root (losetup,
mount), qemu-system-x86_64 and curl. Takes a few minutes with KVM, ~15
without (TCG). Exit status 0 = every check passed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.cookiejar
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path

# frfw.kernel_boot stages a kernel onto the stick from the host, the way
# the router does (ROADMAP SEC-14) -- from this checkout, as
# scripts/verify-medium.py uses it.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from frfw import kernel_boot  # noqa: E402

#: The router's LAN address, reached over the host's tap device.
WEBUI_HOST = "192.168.1.1"
WEBUI_PORT = 443
#: A LAN port nothing allows: the default policy drops it, and the drop
#: must be logged (security-lessons K6).
CLOSED_PORT = 4444
#: The host's side of the VM's LAN port: a "laptop" with no DHCP server.
LAN_TAP = "frtap0"
LAN_TAP_ADDRESS = "192.168.1.2/24"
#: An address beyond the router (TEST-NET-2, RFC 5737), routed from the
#: host through the VM, so what the host sends it is forwarded traffic.
#: The router's address in the VPN tunnel (security-lessons G8/K5), set
#: in boot 3. Reached from the host through the router: only the webUI
#: restarted by that apply listens on it.
VPN_ADDRESS = "10.99.0.1"
BEYOND_NET = "198.51.100.0/24"
BEYOND_HOST = "198.51.100.7"
NEW_PASSWORD = "changed-in-boot-3"
NEW_USERNAME = "netadmin"
#: A ZTNA user made through the webUI, signed in from the host's tap
#: (ROADMAP SEC-6).
ZTNA_USERNAME = "fieldworker"
ZTNA_PASSWORD = "otter-harbor-lamp-71"
#: An interface on a device the VM doesn't have, saved in boot 3: its
#: apply is refused, and boot 4 can't apply config.yaml (ROADMAP SEC-5).
#: ROADMAP SEC-27: a LAN address the webUI's address can't be taken away
#: by -- in the same subnet, so it is only the webUI address that refuses it.
MOVED_LAN_ADDRESS = "192.168.1.3"
SPARE_DEVICE = "ens9"
SPARE_ADDRESS = "10.250.0.1/24"
DISK_SIZE = 2 * 2**30
#: UEFI firmware for --uefi: Debian 12 / Ubuntu 24.04 name it with _4M.
OVMF = [(Path("/usr/share/OVMF") / f"OVMF_CODE{s}.fd", Path("/usr/share/OVMF") / f"OVMF_VARS{s}.fd")
        for s in ("_4M", "")]
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
    def __init__(self, workdir: Path, disk: Path, n: int, kvm: bool, uefi: tuple[Path, Path] | None = None) -> None:
        self.serial = workdir / f"boot{n}.log"
        self.monitor = workdir / f"mon{n}.sock"
        cmd = [
            "qemu-system-x86_64", "-m", "2048", "-smp", "2", "-no-reboot",
            "-nic", "user,model=virtio-net-pci,mac=52:54:00:00:00:01",
            # The LAN port: the host's tap, no DHCP server on it -- QEMU's
            # user network always runs one, which would make both ports
            # look like an upstream (ROADMAP SEC-8).
            "-netdev", f"tap,id=lan,ifname={LAN_TAP},script=no,downscript=no",
            "-device", "virtio-net-pci,netdev=lan,mac=52:54:00:00:00:02",
            # The stick, booted first whatever the firmware's own order
            # (OVMF would try the NICs' network boot too). After the NICs:
            # devices take PCI slots in this order, and the NICs' slots are
            # their names -- WAN ens3, LAN ens4.
            "-drive", f"file={disk},format=raw,if=none,id=stick",
            "-device", "virtio-blk-pci,drive=stick,bootindex=0",
            # A hardware watchdog for systemd to keep fed (ROADMAP SEC-14);
            # after the stick, so the NICs keep their slots.
            "-device", "i6300esb",
            "-display", "none", "-serial", f"file:{self.serial}",
            "-monitor", f"unix:{self.monitor},server,nowait",
        ]
        if kvm:
            cmd[1:1] = ["-enable-kvm", "-cpu", "host"]
        if uefi:
            # The machine's own firmware variables, kept across its boots.
            code, variables = uefi
            cmd += ["-drive", f"if=pflash,format=raw,readonly=on,file={code}",
                    "-drive", f"if=pflash,format=raw,file={variables}"]
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
def lan_tap():
    """The host's side of the VM's LAN port, for every boot."""
    subprocess.run(["ip", "link", "del", LAN_TAP], capture_output=True)
    subprocess.run(["ip", "tuntap", "add", "dev", LAN_TAP, "mode", "tap"], check=True)
    try:
        subprocess.run(["ip", "addr", "add", LAN_TAP_ADDRESS, "dev", LAN_TAP], check=True)
        subprocess.run(["ip", "link", "set", LAN_TAP, "up"], check=True)
        subprocess.run(["ip", "route", "add", BEYOND_NET, "via", WEBUI_HOST, "dev", LAN_TAP], check=True)
        subprocess.run(["ip", "route", "add", f"{VPN_ADDRESS}/32", "via", WEBUI_HOST, "dev", LAN_TAP], check=True)
        yield
    finally:
        subprocess.run(["ip", "link", "del", LAN_TAP], capture_output=True)


@contextmanager
def persistence_partition(disk: Path, *, writable: bool = False):
    """Mount partition 3 (the persistence one) of the disk image -- read-only
    unless `writable` (planting the boot test's implant, ROADMAP SEC-15)."""
    loop = subprocess.run(["losetup", "--find", "--show", str(disk)], check=True,
                          capture_output=True, text=True).stdout.strip()
    mountpoint = Path(tempfile.mkdtemp(prefix="fros-p3-"))
    try:
        # The hybrid ISO's partition 1 starts at sector 0; the kernel's
        # own scan skips partition 2, so add partition 3 explicitly.
        subprocess.run(["partx", "--add", "--nr", "3", loop], capture_output=True)
        subprocess.run(["mount", "-o", "rw" if writable else "ro", f"{loop}p3", str(mountpoint)], check=True)
        try:
            yield mountpoint / "rw"  # live-boot's overlay upper directory
        finally:
            subprocess.run(["umount", str(mountpoint)], check=False)
    finally:
        subprocess.run(["losetup", "--detach", loop], check=False)
        mountpoint.rmdir()


#: ROADMAP SEC-15: a module planted on the persistence partition after
#: boot 3, the way an attacker's implant would sit next to FR_OS's own;
#: the router's own check (boot 4) and the offline one must find it.
IMPLANT = "usr/local/lib/python3.11/dist-packages/frfw/zz_implant.py"


@contextmanager
def iso_contents(iso: Path):
    """The ISO 9660 file system itself (live/vmlinuz, live/initrd.img)."""
    mountpoint = Path(tempfile.mkdtemp(prefix="fros-iso-"))
    try:
        subprocess.run(["mount", "-o", "loop,ro", str(iso), str(mountpoint)], check=True)
    except subprocess.CalledProcessError:
        mountpoint.rmdir()
        raise
    try:
        yield mountpoint
    finally:
        _unmount(mountpoint)


def stage_kernel(disk: Path, iso: Path, version: str, *, broken_initrd: bool = False) -> None:
    """Stage the image's own kernel on the stick's persistence partition
    with frfw.kernel_boot.stage() (ROADMAP SEC-14) -- or with an initrd
    that is not one, so the kernel finds no root file system and panics."""
    with iso_contents(iso) as contents, persistence_partition(disk, writable=True) as upper:
        initrd = contents / "live" / "initrd.img"
        if broken_initrd:
            initrd = Path(tempfile.mkdtemp(prefix="fros-initrd-")) / "initrd.img"
            initrd.write_bytes(b"not an initramfs" * 4096)
        kernel_boot.stage(contents / "live" / "vmlinuz", initrd, version,
                          boot_dir=upper.parent / kernel_boot.BOOT_DIR_NAME)


def kernel_env(upper: Path) -> dict[str, str]:
    return kernel_boot.read_env(upper.parent / kernel_boot.BOOT_DIR_NAME / kernel_boot.ENV_NAME)


def command_line(log: str) -> list[str]:
    return log.split("Command line:", 1)[-1].split("\n", 1)[0].split()


#: Masks the webUI for boot 6: a staged kernel's boot then fails its check.
WEBUI_UNIT = Path("etc") / "systemd" / "system" / "fr-webui.service"


def verify_medium(disk: Path) -> dict:
    """scripts/verify-medium.py on the stick, as from another computer:
    the result, or {"error": ...}."""
    proc = subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / "scripts" / "verify-medium.py"),
                           str(disk), "--json"], capture_output=True, text=True)
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": (proc.stderr or proc.stdout).strip()[-300:]}


def group_id(upper: Path, name: str) -> int | None:
    """A group's id, from the router's own /etc/group (FR_OS creates its
    accounts at boot, so the file is on the persistence layer)."""
    group_file = upper / "etc" / "group"
    for line in group_file.read_text().splitlines() if group_file.exists() else []:
        fields = line.split(":")
        if len(fields) >= 3 and fields[0] == name:
            return int(fields[2])
    return None


def group_members(upper: Path, name: str) -> set[str]:
    group_file = upper / "etc" / "group"
    for line in group_file.read_text().splitlines() if group_file.exists() else []:
        fields = line.split(":")
        if len(fields) >= 4 and fields[0] == name:
            return {m for m in fields[3].split(",") if m}
    return set()


def check_sni_event_file(check, upper: Path) -> None:
    """ROADMAP SEC-4: fr-xdp-sni-logger's event file, which the webUI and
    the sensor daemons read instead of the journal, is root's and
    readable by their shared group only (fr_os-feeds since ROADMAP
    SEC-11) -- no reader can write it."""
    directory = upper / "var" / "log" / "fr_os-sni"
    events = directory / "events.jsonl"
    feeds_gid = group_id(upper, "fr_os-feeds")
    ok = (events.exists() and feeds_gid is not None
          and events.stat().st_uid == 0 and events.stat().st_gid == feeds_gid
          and events.stat().st_mode & 0o777 == 0o640
          and directory.stat().st_uid == 0 and directory.stat().st_gid == feeds_gid
          and directory.stat().st_mode & 0o777 == 0o750)
    detail = ""
    if not ok and events.exists():
        st = events.stat()
        detail = f": {st.st_uid}:{st.st_gid} {oct(st.st_mode & 0o777)} (fr_os-feeds is {feeds_gid})"
    check(ok, "the XDP SNI event file is root:fr_os-feeds 0640 (ROADMAP SEC-4, SEC-11)" + detail)


def check_sensor_isolation(check, upper: Path, *, secret: str | None = None) -> None:
    """ROADMAP SEC-11: the parser daemons' account is in no group of the
    webUI's -- only fr_os-feeds -- and reads its configuration from a copy
    without secrets, root:fr_os-sensor 0640; config.yaml stays
    root:fr_os-webui 0640. With `secret`, a value config.yaml has that
    the copy must not."""
    webui = group_members(upper, "fr_os-webui")
    feeds = group_members(upper, "fr_os-feeds")
    check("fr_os-sensor" not in webui and {"fr_os-sensor", "fr_os-webui"} <= feeds,
          "the sensor account is in fr_os-feeds and not in the webUI's group (ROADMAP SEC-11)"
          + f": fr_os-webui members {sorted(webui)}, fr_os-feeds members {sorted(feeds)}")
    config, copy = upper / "etc" / "fr_os" / "config.yaml", upper / "etc" / "fr_os" / "sensor-config.yaml"
    sensor_gid, webui_gid = group_id(upper, "fr_os-sensor"), group_id(upper, "fr_os-webui")

    def owned(path: Path, gid: int | None) -> bool:
        st = path.stat()
        return st.st_uid == 0 and st.st_gid == gid and st.st_mode & 0o777 == 0o640

    ok = copy.exists() and config.exists() and owned(copy, sensor_gid) and owned(config, webui_gid)
    if ok and secret is not None:
        ok = secret in config.read_text() and secret not in copy.read_text()
    check(ok, "the sensors read a copy of the config without its secrets, root:fr_os-sensor 0640 (ROADMAP SEC-11)"
          + ("" if secret is None else ", the metrics token's digest left out"))


#: ROADMAP P4-1: the XDP SNI filter is turned on in boot 3 with this one
#: name blocked, on the LAN port the boot test reaches the webUI through.
XDP_BLOCKED_NAME = "blocked.fr-os.test"
XDP_ALLOWED_NAME = "allowed.fr-os.test"


def tls_handshake(server_name: str, timeout: float = 8) -> bool:
    """Whether a TLS handshake with the router's webUI completes when the
    ClientHello names `server_name` -- the XDP filter on the LAN port
    drops a blocked name's ClientHello, so that handshake never does."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((WEBUI_HOST, WEBUI_PORT), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=server_name):
                return True
    except OSError:  # a timeout, or a TLS error
        return False


def _vec16(data: bytes) -> bytes:
    return struct.pack("!H", len(data)) + data


def split_client_hello(server_name: str) -> tuple[bytes, int]:
    """A browser-sized TLS ClientHello record -- an X25519MLKEM768 key
    share makes it larger than one segment -- with its server_name
    extension last, and where to cut it so the name is wholly in the
    second segment (ROADMAP SEC-17). Built from RFC 8446 structures."""
    def ext(ext_type: int, body: bytes) -> bytes:
        return struct.pack("!H", ext_type) + _vec16(body)

    shares = struct.pack("!H", 0x11EC) + _vec16(bytes(1216)) + struct.pack("!H", 0x001D) + _vec16(os.urandom(32))
    sni = ext(0x0000, _vec16(b"\x00" + _vec16(server_name.encode())))
    extensions = (
        ext(0x000A, _vec16(struct.pack("!HH", 0x11EC, 0x001D)))       # supported_groups
        + ext(0x000D, _vec16(struct.pack("!HHH", 0x0403, 0x0804, 0x0401)))  # signature_algorithms
        + ext(0x002B, b"\x02\x03\x04")                               # supported_versions: TLS 1.3
        + ext(0x0015, bytes(200))                                      # padding (RFC 7685), as Chrome sends
        + ext(0x0033, _vec16(shares))                                  # key_share
        + sni
    )
    body = (b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32)
            + _vec16(struct.pack("!HHH", 0x1301, 0x1302, 0x1303)) + b"\x01\x00" + _vec16(extensions))
    message = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record = b"\x16\x03\x01" + _vec16(message)
    return record, record.index(sni) - 300


def split_hello_answered(server_name: str, timeout: float = 5) -> bool:
    """Send split_client_hello() to the webUI in two segments: whether its
    TLS server answers at all (a ServerHello or an alert) -- it does once
    it has the whole hello, which the XDP filter must stop for a blocked
    name. Closes with an RST, so nothing is retransmitted afterwards."""
    record, cut = split_client_hello(server_name)
    try:
        with socket.create_connection((WEBUI_HOST, WEBUI_PORT), timeout=timeout) as conn:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            conn.sendall(record[:cut])
            time.sleep(0.2)
            conn.sendall(record[cut:])
            return len(conn.recv(1)) == 1
    except OSError:  # a timeout: no answer
        return False


def udp_through_router(port: int, timeout: float = 3) -> str:
    """Send one datagram to BEYOND_HOST, through the router: "refused"
    when a port unreachable comes back (the router's `reject`), "answered"
    or "no answer" (nothing, or another ICMP error from upstream)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((BEYOND_HOST, port))
        try:
            sock.send(b"\xc0" + os.urandom(1199))  # the size of a QUIC Initial
            sock.recv(1)
            return "answered"
        except ConnectionRefusedError:
            return "refused"
        except OSError:
            return "no answer"


def xdp_blocked_events(upper: Path) -> list[str]:
    """The SNI event file's lines for the boot test's blocked name."""
    events = upper / "var" / "log" / "fr_os-sni" / "events.jsonl"
    text = events.read_text() if events.exists() else ""
    return [line for line in text.splitlines() if f'"sni": "{XDP_BLOCKED_NAME}"' in line]


def first_stream_line(opener) -> str:
    """The first line of the webUI's live XDP log stream: recent events,
    or the keep-alive the stream sends within 15 s on a quiet log."""
    with opener.open(f"https://{WEBUI_HOST}:{WEBUI_PORT}/xdp/logs/stream", timeout=40) as resp:
        return resp.readline().decode()


def _unmount(mountpoint: Path) -> None:
    """Unmount and remove a temporary mount point. The loop device under a
    squashfs mounted from a file on another mount is released
    asynchronously, so that other mount reports "target is busy" for a
    moment after the squashfs is gone: retry for a few seconds, then
    detach it lazily rather than fail the boot test over its cleanup."""
    for _ in range(20):
        if subprocess.run(["umount", str(mountpoint)], capture_output=True).returncode == 0:
            break
        time.sleep(0.5)
    else:
        subprocess.run(["umount", "--lazy", str(mountpoint)], check=False)
    mountpoint.rmdir()


@contextmanager
def image_root(iso: Path):
    """The image's root filesystem (live/filesystem.squashfs), mounted
    read-only -- what every boot starts from before persistence."""
    iso_mount = Path(tempfile.mkdtemp(prefix="fros-iso-"))
    try:
        subprocess.run(["mount", "-o", "loop,ro", str(iso), str(iso_mount)], check=True)
    except subprocess.CalledProcessError:
        iso_mount.rmdir()
        raise
    try:
        root = Path(tempfile.mkdtemp(prefix="fros-root-"))
        try:
            subprocess.run(["mount", "-t", "squashfs", "-o", "loop,ro",
                            str(iso_mount / "live" / "filesystem.squashfs"), str(root)], check=True)
        except subprocess.CalledProcessError:
            root.rmdir()
            raise
        try:
            yield root
        finally:
            _unmount(root)
    finally:
        _unmount(iso_mount)


#: Debian's own ruleset loader (ROADMAP SEC-18).
NFTABLES_UNIT = Path("etc") / "systemd" / "system" / "nftables.service"


def nftables_unit_masked(root: Path, upper: Path) -> bool:
    """Debian's nftables.service is masked in the image, and the
    persistence layer doesn't undo that: a mask is a symlink to
    /dev/null, and live-boot's overlay would show an unmask as the link
    gone (a whiteout) or replaced in the upper directory."""
    masked = (root / NFTABLES_UNIT).is_symlink() and os.readlink(root / NFTABLES_UNIT) == "/dev/null"
    override = upper / NFTABLES_UNIT
    kept = not os.path.lexists(override) or (override.is_symlink() and os.readlink(override) == "/dev/null")
    return masked and kept


def journal(upper: Path, *args: str) -> str:
    return subprocess.run(
        ["journalctl", f"--directory={upper}/var/log/journal", "--no-pager", "-o", "cat", *args],
        capture_output=True, text=True,
    ).stdout


def print_journal(upper: Path, unit: str, *boot: str) -> None:
    """The unit's last journal lines, timestamped, into the CI log: the
    QEMU artifacts are not always at hand when a check fails."""
    print(f"    --- journal of {unit} ---")
    for line in journal(upper, *boot, "-u", unit, "-o", "short-monotonic").splitlines()[-25:]:
        print(f"    {line}")


#: FR_OS services that must be running after a boot, each in its systemd
#: sandbox (security-lessons I1).
#: (fr-apply-helper is socket-activated: it starts on first use.)
LONG_RUNNING = ("fr-webui", "fr-ai-ids", "fr-appid", "fr-tls-fp", "fr-xdp-sni-logger")


def check_sandboxed_services(check, upper: Path, *boot: str) -> None:
    """No FR_OS service was killed by its sandbox or crashed, and the
    long-running ones started (security-lessons I1). A syscall the
    filter doesn't allow fails with EPERM; a service that can't live with
    that exits, and systemd says so."""
    text = journal(upper, *boot, "-u", "fr-*")
    bad = sorted(set(re.findall(r"(fr-[\w-]+)\.service: (?:Main process exited, code=killed|Failed with result)",
                                text)))
    check(not bad, "no FR_OS service crashed or was killed in its sandbox"
          + (f": {', '.join(bad)}" if bad else ""))
    # Say why, right here in the CI log. fr-webui-rebind only restarts
    # fr-webui, so its failure is told by fr-webui's own journal.
    for unit in bad + (["fr-webui"] if "fr-webui-rebind" in bad else []):
        print_journal(upper, f"{unit}.service", *boot)
    check("status=31/SYS" not in text, "no seccomp kill")
    for unit in LONG_RUNNING:
        check("Started" in journal(upper, *boot, "-u", f"{unit}.service"), f"{unit} started")
    firewall = journal(upper, *boot, "-u", "fr-firewall.service") + journal(upper, *boot, "-u", "fr-apply-helper.service")
    check("Permission denied" not in firewall and "Read-only file system" not in firewall,
          "applying the config hit no sandbox wall (EPERM/EROFS)")


def webui_opener() -> urllib.request.OpenerDirector:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # the router's self-signed certificate
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
    )


def wait_for_rebind(timeout: float) -> bool:
    """Whether the webUI restarted onto the VPN's address within `timeout`.
    The apply that turns the VPN on schedules that restart a few seconds
    later; until it has happened, the old process still answers on the
    LAN address -- waiting for that one let the checks after it run into
    the restart. Only the new process listens on VPN_ADDRESS."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection((VPN_ADDRESS, WEBUI_PORT), timeout=3).close()
            return True
        except OSError:
            time.sleep(1)
    return False


def confirm_pending(opener) -> bool:
    """Confirm the apply waiting for confirmation from the dashboard, as an
    admin does (ROADMAP SEC-26): whether it is no longer waiting."""
    held = re.search(r'action="/apply/confirm".*?name="id" value="([0-9a-f]+)"', get(opener, "/"), re.S)
    if held is None:
        return False
    confirmed = urllib.parse.unquote_plus(post(opener, "/apply/confirm", {"id": held.group(1)}))
    return "Apply confirmed" in confirmed and "waiting for confirmation" not in get(opener, "/")


def wait_until_unreachable(host: str, timeout: float) -> bool:
    """Whether the webUI stops answering at `host` within `timeout` -- an
    apply that moved it restarts it a few seconds later (ROADMAP SEC-26)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection((host, WEBUI_PORT), timeout=3).close()
        except OSError:
            return True
        time.sleep(1)
    return False


def wait_for_webui(opener, timeout: float) -> str | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with opener.open(f"https://{WEBUI_HOST}:{WEBUI_PORT}/login", timeout=10) as resp:
                return resp.read().decode()
        except OSError:
            time.sleep(5)
    return None


#: The session's CSRF token, as the webUI renders it into every page it
#: serves a logged-in session (the hidden field every form carries).
_CSRF_FIELD = re.compile(r'name="csrf_token" value="([^"]+)"')


def _remember_csrf(opener, page: str) -> None:
    """Keep the CSRF token of the page just served, like the browser's
    form would: the webUI refuses a state-changing request without the
    session's token (security-lessons H1, ROADMAP SEC-9), and the token
    changes with the session, e.g. after first-run setup."""
    match = _CSRF_FIELD.search(page)
    if match:
        opener.csrf_token = match.group(1)


def get(opener, path: str) -> str:
    with opener.open(f"https://{WEBUI_HOST}:{WEBUI_PORT}{path}", timeout=60) as resp:
        page = resp.read().decode()
    _remember_csrf(opener, page)
    return page


def post(opener, path: str, fields: dict) -> str:
    """Submit a form the way the page's own form does -- with the
    session's CSRF token -- and return the URL it lands on (the page
    itself is kept as `opener.last_page`)."""
    token = getattr(opener, "csrf_token", "")
    if token:
        fields = {**fields, "csrf_token": token}
    data = urllib.parse.urlencode(fields, doseq=True).encode()
    with opener.open(f"https://{WEBUI_HOST}:{WEBUI_PORT}{path}", data=data, timeout=30) as resp:
        opener.last_page = resp.read().decode()
        _remember_csrf(opener, opener.last_page)
        return resp.geturl()


def scrape_metrics(token: str | None = None) -> tuple[int, str]:
    """GET /metrics the way a Prometheus does -- no session, the bearer
    token if any: (HTTP status, body)."""
    request = urllib.request.Request(f"https://{WEBUI_HOST}:{WEBUI_PORT}/metrics")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(request, timeout=30, context=context) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode()


def run_kernel_trials(check, workdir: Path, disk: Path, iso: Path, kvm: bool, uefi, boot_timeout: float) -> None:
    """Boots 5-8: a kernel staged on the persistence partition, tried and
    kept, tried and failed by the router's own check, the fallback after
    it, and one that panics (ROADMAP SEC-14)."""
    version = re.search(r"Linux version (\S+)", (workdir / "boot4.log").read_text(errors="replace"))
    version = version.group(1) if version else "0.0.0-fros-test"

    print(f"boot 5: kernel {version}, staged on the persistence partition, on its trial boot")
    stage_kernel(disk, iso, version)
    vm = Vm(workdir, disk, 5, kvm, uefi)
    page = wait_for_webui(webui_opener(), boot_timeout)
    log = vm.log()
    cmdline = command_line(log)
    check("fr_os.kernel=trial" in cmdline and "panic=10" in cmdline,
          "GRUB booted the staged kernel for its trial (fr_os.kernel=trial, panic=10)")
    check(page is not None, "...and the router came up on it")
    # Not powered off before the router confirmed it: a trial cut short
    # is a trial that didn't come up (the next boot falls back).
    opener = webui_opener()
    landed = post(opener, "/login", {"username": NEW_USERNAME, "password": NEW_PASSWORD}) if page else ""
    check(landed.endswith("/") and wait_confirmed(opener), "...and the Update screen says it is confirmed")
    check(vm.power_off(), "powered off")
    vm.kill()
    with persistence_partition(disk) as upper:
        confirm = journal(upper, "-b", "-u", "fr-kernel-confirm.service")
        check(f"kernel {version} confirmed" in confirm and kernel_env(upper).get("fr_os_state") == "good",
              "the router confirmed it late in the boot: it is the router's kernel now (state 'good')")
        if "confirmed" not in confirm:
            print_journal(upper, "fr-kernel-confirm.service", "-b")
        watchdog = re.search(r".*[Hh]ardware watchdog.*", journal(upper, "-b", "_PID=1"))
        check(watchdog is not None and "i6300ESB" in watchdog.group(0),
              "systemd keeps the hardware watchdog fed" + (f": {watchdog.group(0).strip()}" if watchdog else ""))

    print("boot 6: a new trial, with the webUI masked -- the router doesn't come up")
    stage_kernel(disk, iso, version)
    with persistence_partition(disk, writable=True) as upper:
        unit = upper / WEBUI_UNIT
        unit.parent.mkdir(parents=True, exist_ok=True)
        saved = unit.read_bytes() if unit.exists() and not unit.is_symlink() else None
        unit.unlink(missing_ok=True)
        unit.symlink_to("/dev/null")
    vm = Vm(workdir, disk, 6, kvm, uefi)
    rebooted = vm.wait_exit(boot_timeout + kernel_boot.HEALTH_TIMEOUT + 60)
    vm.kill()
    log = vm.log()
    check("fr_os.kernel=trial" in command_line(log), "GRUB booted the staged kernel for its trial")
    check(rebooted, "the router rebooted by itself when its check failed")
    with persistence_partition(disk, writable=True) as upper:
        confirm = journal(upper, "-b", "-u", "fr-kernel-confirm.service")
        check("failed its trial boot (the webUI does not answer)" in confirm, "...because the webUI did not answer")
        if "failed its trial" not in confirm:
            print_journal(upper, "fr-kernel-confirm.service", "-b")
        check(kernel_env(upper).get("fr_os_state") == "trying", "...leaving the trial unconfirmed ('trying')")
        unit = upper / WEBUI_UNIT
        unit.unlink()
        if saved is not None:
            unit.write_bytes(saved)

    print("boot 7: after the failed trial")
    vm = Vm(workdir, disk, 7, kvm, uefi)
    opener = webui_opener()
    page = wait_for_webui(opener, boot_timeout)
    log = vm.log()
    check("fr_os.kernel=fallback" in command_line(log) and "panic=10" not in command_line(log),
          "GRUB booted the image's own kernel instead (fr_os.kernel=fallback)")
    check(page is not None, "...and the webUI answers")
    check(vm.power_off(), "powered off")
    vm.kill()
    with persistence_partition(disk) as upper:
        check(kernel_env(upper).get("fr_os_state") == "failed", "the staged kernel is marked 'failed'")
        audit_log = (upper / "var" / "log" / "fr_os" / "audit.log").read_text()
        check("failed its trial boot" in audit_log and f"kernel {version} did not come up" in audit_log,
              "both are security alerts: the failed trial, and the fallback boot")

    print("boot 8: a staged kernel whose initrd is broken")
    stage_kernel(disk, iso, version, broken_initrd=True)
    vm = Vm(workdir, disk, 8, kvm, uefi)
    rebooted = vm.wait_exit(boot_timeout)
    vm.kill()
    log = vm.log()
    check("fr_os.kernel=trial" in command_line(log) and "Kernel panic" in log,
          "the staged kernel panicked on its trial boot")
    check(rebooted, "...and rebooted by itself (panic=10)")
    with persistence_partition(disk) as upper:
        check(kernel_env(upper).get("fr_os_state") == "trying",
              "GRUB recorded the try first ('trying'): the next boot is the image's own kernel")


def wait_confirmed(opener, timeout: float = kernel_boot.HEALTH_TIMEOUT) -> bool:
    """Until the Update screen says the staged kernel is confirmed."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if "confirmed: boots by default" in get(opener, "/update"):
            return True
        time.sleep(3)
    return False


def print_serial_tail(log: str, lines: int = 120) -> None:
    """The end of a boot's serial console, in the CI log (its artifacts
    can't always be fetched)."""
    print("---- serial console, last lines ----")
    print("\n".join(log.replace("\r", "").splitlines()[-lines:]))
    print("---- end of serial console ----")


def compare_initrds(iso: Path, built: Path) -> None:
    """What the initrd the router built has, or lacks, compared with the
    image's own -- printed, for a trial that doesn't come up."""
    if not shutil.which("lsinitramfs") or not built.is_file():
        print(f"(initrd comparison skipped: lsinitramfs {'missing' if not shutil.which('lsinitramfs') else 'ok'}, "
              f"{built} {'there' if built.is_file() else 'missing'})")
        return
    with iso_contents(iso) as contents:
        image = set(subprocess.run(["lsinitramfs", str(contents / "live" / "initrd.img")],
                                   capture_output=True, text=True).stdout.split())
    router = set(subprocess.run(["lsinitramfs", str(built)], capture_output=True, text=True).stdout.split())
    print(f"initrd: image {len(image)} entries, router-built {len(router)} ({built.stat().st_size} bytes)")
    only_image = sorted(path for path in image - router if "/kernel/" not in path)
    only_router = sorted(path for path in router - image if "/kernel/" not in path)
    print("  only in the image's (not modules):", only_image[:80])
    print("  only in the router's (not modules):", only_router[:80])
    print(f"  modules: image {sum('/kernel/' in p for p in image)}, router {sum('/kernel/' in p for p in router)}")


#: Points fr-kernel-prepare at the running kernel for boots 9-10: the
#: router prepares it without the network (no newer Debian kernel is
#: needed to test the path).
PREPARE_DROPIN = Path("etc") / "systemd" / "system" / "fr-kernel-prepare.service.d" / "boot-test.conf"


def run_kernel_update_from_the_webui(check, workdir: Path, disk: Path, iso_path: Path, kvm: bool, uefi,
                                     boot_timeout: float) -> None:
    """Boots 9-10: the Update screen's kernel card -- "Check now", the
    router builds the kernel's initrd itself, "Try it" reboots into the
    trial, and the router keeps it (ROADMAP SEC-14, step 3)."""
    version = re.search(r"Linux version (\S+)", (workdir / "boot4.log").read_text(errors="replace"))
    version = version.group(1) if version else "0.0.0-fros-test"
    with persistence_partition(disk, writable=True) as upper:
        # The admin's "back to the image's kernel": boot 8's broken
        # trial is the same version, and a failed one is never tried again.
        kernel_boot.unstage(boot_dir=upper.parent / kernel_boot.BOOT_DIR_NAME)
        dropin = upper / PREPARE_DROPIN
        dropin.parent.mkdir(parents=True, exist_ok=True)
        dropin.write_text(f"[Service]\nExecStart=\nExecStart=firewall-cli kernel prepare --version {version}\n")

    print("boot 9: the Update screen's kernel card -- check, ready, try")
    vm = Vm(workdir, disk, 9, kvm, uefi)
    opener = webui_opener()
    page = wait_for_webui(opener, boot_timeout)
    landed = post(opener, "/login", {"username": NEW_USERNAME, "password": NEW_PASSWORD}) if page else ""
    check(landed.endswith("/"), "signed in")
    ready = False
    if landed:
        post(opener, "/update/kernel/check", {})
        deadline = time.monotonic() + 600
        card = ""
        while time.monotonic() < deadline:
            card = get(opener, "/update").split('id="kernel"', 1)[-1].split("</div>", 1)[0]
            if 'id="kernel-try"' in card or "failed" in card:
                break
            time.sleep(10)
        ready = 'id="kernel-try"' in card
        check(ready, f"the router prepared kernel {version} itself -- its initrd the image's own with that "
                     "kernel's modules -- and the Update screen offers to try it"
              + ("" if ready else f": {re.sub(r'<[^>]+>', ' ', card)[:400]}"))
    if ready:
        post(opener, "/update/kernel/try", {})
    rebooted = vm.wait_exit(boot_timeout)
    vm.kill()
    check(ready and rebooted, "\"Try it\" rebooted the router into the trial")
    with persistence_partition(disk, writable=True) as upper:
        prepare = journal(upper, "-b", "-u", "fr-kernel-prepare.service")
        if not ready:
            print(prepare[-3000:])
        audit_log = (upper / "var" / "log" / "fr_os" / "audit.log").read_text()
        check(f"kernel {version} is ready to try" in audit_log and f"kernel {version} staged from the webUI" in audit_log,
              "both are in the security alerts: the kernel ready, and the trial started from the webUI")
        (upper / PREPARE_DROPIN).unlink()
        (upper / PREPARE_DROPIN).parent.rmdir()
        compare_initrds(iso_path, upper.parent / kernel_boot.BOOT_DIR_NAME / kernel_boot.SLOT / kernel_boot.INITRD)
    if not ready:
        return

    print("boot 10: the trial of the kernel the router prepared")
    vm = Vm(workdir, disk, 10, kvm, uefi)
    opener = webui_opener()
    page = wait_for_webui(opener, boot_timeout)
    log = vm.log()
    check("fr_os.kernel=trial" in command_line(log), "GRUB booted it for its trial")
    check(page is not None, "...the router came up on its own initrd")
    landed = post(opener, "/login", {"username": NEW_USERNAME, "password": NEW_PASSWORD}) if page else ""
    confirmed = bool(landed) and wait_confirmed(opener)
    check(confirmed, "...and the Update screen says it is confirmed: the router's kernel now")
    running = vm.proc.poll() is None
    check(running and vm.power_off(), "powered off" if running else "powered off (it had already stopped by itself)")
    vm.kill()
    if page is None or not confirmed:
        print_serial_tail(vm.log())
    with persistence_partition(disk) as upper:
        check(kernel_env(upper).get("fr_os_state") == "good", "the boot environment agrees ('good')"
              + f": {kernel_env(upper).get('fr_os_state')!r}")
        if page is None or not confirmed:
            print(journal(upper, "-b", "-p", "warning")[-4000:])
            print_journal(upper, "fr-kernel-confirm.service", "-b")


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("iso", type=Path)
    parser.add_argument("--workdir", type=Path, help="keep the disk image and serial logs here")
    parser.add_argument("--kvm", action="store_true", help="use KVM (much faster) if /dev/kvm exists")
    parser.add_argument("--uefi", action="store_true", help="boot with UEFI firmware (OVMF) instead of BIOS")
    parser.add_argument("--signed-build", action="store_true",
                        help="the image carries a signed release (a release run): check it (ROADMAP SEC-15)")
    args = parser.parse_args()
    if not shutil.which("qemu-system-x86_64"):
        print("qemu-system-x86_64 not found", file=sys.stderr)
        return 2
    if args.uefi and not any(c.is_file() and v.is_file() for c, v in OVMF):
        print("--uefi: no OVMF firmware (install the ovmf package)", file=sys.stderr)
        return 2
    with lan_tap():
        return run(args)


def run(args: argparse.Namespace) -> int:
    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="fros-qemu-"))
    workdir.mkdir(parents=True, exist_ok=True)
    # ROADMAP SEC-15: a release run signs the source the image carries
    # (--signed-build; the CI's test builds are unsigned since review
    # v0.2.1 FR-NEW-002) -- or a SHA256SUMS.sig sits next to the ISO.
    signed_build = args.signed_build or (Path(args.iso).resolve().parent / "SHA256SUMS.sig").is_file()
    print(f"signed build: {signed_build}")
    disk = workdir / "stick.img"
    shutil.copyfile(args.iso, disk)
    with disk.open("r+b") as fh:
        fh.truncate(DISK_SIZE)
    kvm = args.kvm and Path("/dev/kvm").exists()
    uefi = None
    if args.uefi:
        code, variables = next((c, v) for c, v in OVMF if c.is_file() and v.is_file())
        uefi = (code, workdir / "OVMF_VARS.fd")
        shutil.copyfile(variables, uefi[1])
    boot_timeout = 300 if kvm else 900
    check = Check()
    print(f"work directory: {workdir} ({'KVM' if kvm else 'TCG, slow'}, {'UEFI' if uefi else 'BIOS'})")

    print("boot 1: persistence setup")
    vm = Vm(workdir, disk, 1, kvm, uefi)
    rebooted = vm.wait_exit(boot_timeout)
    vm.kill()
    log = vm.log()
    cmdline = log.split("Command line:", 1)[-1].split("\n", 1)[0].split()
    check("boot=live" in cmdline and "persistence" in cmdline and "nosmp" not in cmdline,
          "booted the normal menu entry with the persistence option")
    loader = "grub-efi" if uefi else "grub-pc"
    check(f"fr_os.loader={loader}" in cmdline,
          f"the kernel came from GRUB's menu ({loader}, ROADMAP SEC-14): "
          + next((o for o in cmdline if o.startswith("fr_os.loader=")), "no fr_os.loader= option"))
    check("fr-persistence: created" in log, "created the persistence partition on the boot medium")
    check(rebooted, "rebooted by itself to start using it")

    print("boot 2: first boot")
    vm = Vm(workdir, disk, 2, kvm, uefi)
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
        # ROADMAP SEC-8: the WAN is the port where a DHCP server answered
        # (QEMU's user network), not the first one by chance.
        chosen = re.search(r"fr-first-boot: WAN/LAN: (.*)", first_boot)
        check(chosen is not None and chosen.group(1) == "a DHCP server answered on ens3 only"
              and "assigned WAN=ens3 LAN=ens4" in first_boot,
              "first boot chose the WAN by where a DHCP server answered (ROADMAP SEC-8)"
              + (f": {chosen.group(1)}" if chosen else ""))
        failed = sorted(set(re.findall(r"Failed to start (\S+)", journal(upper))))
        check(not failed, f"no unit failed to start{': ' + ', '.join(failed) if failed else ''}")
        for unit in failed:  # say why, right here in the CI log
            print_journal(upper, unit)
        check_sandboxed_services(check, upper)
        check_sni_event_file(check, upper)
        check_sensor_isolation(check, upper)
        # ROADMAP SEC-4: the resolver's query log has a size cap of its own.
        check("Started" in journal(upper, "-u", "fr-dns-log-trim.timer"),
              "the hourly query-log size cap (fr-dns-log-trim.timer) is running")
        # ROADMAP SEC-21: the daily block-list refresh is armed (it fetches
        # nothing while ad-blocking is off).
        check("Started" in journal(upper, "-u", "fr-adblock-refresh.timer"),
              "the daily ad-block list refresh (fr-adblock-refresh.timer) is armed")
        console = upper / "etc" / "issue.d" / "fr_os-initial-admin.issue"
        shown = console.read_text() if console.exists() else ""
        match = re.search(r"login is 'admin' / '([^']+)'", shown)
        check(match is not None, "admin password shown on the console (/etc/issue.d)")
        password = match.group(1) if match else ""
        check(console.exists() and console.stat().st_mode & 0o077 == 0 and console.stat().st_uid == 0,
              "...in a root-only file")
        check(bool(password) and password not in (upper / "etc" / "issue").read_text(),
              "...and not in the world-readable /etc/issue")
        check((upper / "etc" / "fr_os" / "config.yaml").exists(), "config.yaml is on the persistence partition")
        # A DHCP client on the LAN port flushed the router's own address on
        # the boots after this one (live-boot used to put one on every port).
        wan_dhcp = upper / "etc" / "network" / "interfaces.d" / "fr_os-wan"
        dhcp_text = wan_dhcp.read_text() if wan_dhcp.exists() else ""
        check("iface ens3 inet dhcp" in dhcp_text and "ens4" not in dhcp_text,
              "a DHCP client on the WAN port (ens3) only, never on the LAN port")

    print("boot 3: everything still there")
    vm = Vm(workdir, disk, 3, kvm, uefi)
    opener = webui_opener()
    page = wait_for_webui(opener, boot_timeout)
    check(page is not None, "webUI up again")
    landed = post(opener, "/login", {"username": "admin", "password": password}) if page else ""
    check(landed.endswith("/setup"), "the admin password from boot 2 still works, and leads to first-run setup")
    done = post(opener, "/setup", {"username": NEW_USERNAME, "password": NEW_PASSWORD,
                                   "password_confirm": NEW_PASSWORD}) if landed else ""
    set_up = done.endswith("/segments?first_run=1")  # then the segments offer (security-lessons K4)
    check(set_up, f"setup renamed the account to {NEW_USERNAME!r} with a new password")
    applied = ""
    metrics_digest = None
    if set_up:
        # Security-lessons K7: a fresh FR_OS listens on nothing its config
        # doesn't need.
        surface_page = get(opener, "/surface")
        clean = 'class="flash-success" id="unneeded"' in surface_page
        found = re.search(r'id="unneeded">(.*?)</div>', surface_page, re.S)
        # ROADMAP SEC-15: from the first boot, FR_OS's files are checked
        # against the signed release the image carries (or, in a build
        # without the signing key, said to be unsigned).
        system_page = get(opener, "/system")
        integrity = re.search(r'id="integrity-summary">(.*?)</p>', system_page, re.S)
        integrity_text = " ".join(re.sub(r"<[^>]+>", " ", integrity.group(1)).split()) if integrity else ""
        if signed_build:
            check("installed files match the signed release" in integrity_text,
                  f"the router checks its files against the signed release in the image (ROADMAP SEC-15): "
                  f"{integrity_text[:200] or system_page[:200]}")
        else:
            check("not signed" in system_page, "an unsigned test build says its release is not signed (ROADMAP SEC-15)")
        check(clean, "nothing listens that the config doesn't need (security-lessons K7)"
              + ("" if clean else ": " + " ".join((found.group(1) if found else surface_page[:300]).split())))
        # ROADMAP SEC-4: the webUI has no journal access any more; its
        # live XDP log reads the logger's event file from its sandbox.
        first = first_stream_line(opener)
        check(first.startswith((":", "data: {")) and '"error"' not in first,
              "the webUI's live XDP log stream works without journal access (ROADMAP SEC-4)"
              + ("" if '"error"' not in first and first else f": {first.strip()[:200]!r}"))
        # ROADMAP SEC-3: /metrics is off until a token is generated, and
        # then answers only with it -- the helper-backed values included.
        off_status, _ = scrape_metrics()
        post(opener, "/system/metrics/token", {"action": "generate"})
        token = re.search(r'<code style="user-select:all;">([^<]+)</code>', opener.last_page)
        on_status, on_body = scrape_metrics(token.group(1)) if token else (0, "")
        if token:  # config.yaml keeps its digest; the sensors' copy must not (ROADMAP SEC-11)
            metrics_digest = hashlib.sha256(token.group(1).encode()).hexdigest()
        wrong_status, _ = scrape_metrics("not-the-token")
        check(off_status == 404 and on_status == 200 and "fros_bruteforce_banned_ips" in on_body
              and wrong_status == 401,
              "/metrics is off without a token, and answers only with the one generated (ROADMAP SEC-3): "
              f"HTTP {off_status} / {on_status} / {wrong_status}")
        # ROADMAP SEC-12: the router's own update helper refuses an older
        # release -- before downloading anything, so no network is needed.
        refused = urllib.parse.unquote_plus(post(opener, "/update/apply", {"version": "0.0.1"}))
        check("error=" in refused and "older than the installed" in refused,
              "the update helper refuses to install an older release (ROADMAP SEC-12)"
              + ("" if "older than the installed" in refused else f": {refused[:300]}"))
        score_page = get(opener, "/security")
        score = re.search(r'id="score">(\d+)%', score_page)
        check(score is not None, "the security score page works on the real router (security-lessons K8)"
              + (f": {score.group(1)}%" if score else ""))
        post(opener, "/rules/timezone", {"timezone": "Europe/Budapest"})
        # Security-lessons G8: the WireGuard VPN on Debian's own kernel
        # module (the unit tests use the userspace implementation).
        post(opener, "/vpn/settings", {"enabled": "true", "address": f"{VPN_ADDRESS}/24", "listen_port": "51820",
                                       "endpoint": "vpn.example.net"})
        # Security-lessons K4: the segments offered after setup, on real
        # VLAN devices (802.1Q on the LAN port).
        post(opener, "/segments", {"segment": ["iot", "guest"]})
        device_key = base64.b64encode(os.urandom(32)).decode()
        post(opener, "/vpn/peers/add", {"name": "laptop", "public_key": device_key})
        # ROADMAP P4-1: the XDP SNI filter, on the image's own compiled
        # program, on the LAN port.
        post(opener, "/xdp/settings", {"enabled": "true", "interfaces": ["lan"], "blocklist": XDP_BLOCKED_NAME})
        # ROADMAP SEC-6: the ZTNA gate, with one user, signed in below.
        post(opener, "/ztna/users/add", {"new_username": ZTNA_USERNAME, "new_password": ZTNA_PASSWORD})
        post(opener, "/ztna/settings", {"enabled": "true", "session_ttl_seconds": "3600"})
        try:
            applied = urllib.parse.unquote_plus(post(opener, "/apply", {}))
        except urllib.error.HTTPError as err:
            # The checks below then fail by name, and the apply-helper's
            # journal says why once the VM is off.
            applied = f"POST /apply: HTTP {err.code}"
        check("XDP SNI filter attached to: ens4" in applied,
              "the XDP SNI filter loaded the image's compiled program and attached to the LAN port (ROADMAP P4-1)"
              + ("" if "XDP SNI filter attached" in applied else f": {applied[:300]}"))
        check("WireGuard up: wg0 10.99.0.1/24, UDP 51820, 1 peer(s)" in applied,
              "the VPN came up on the kernel's WireGuard (security-lessons G8)"
              + ("" if "WireGuard up" in applied else f": {applied[:300]}"))
        check(re.search(r"\.30=192\.168\.30\.1/24", applied) is not None
              and re.search(r"\.40=192\.168\.40\.1/24", applied) is not None,
              "the IoT and guest segments came up on VLANs of the LAN port (security-lessons K4)"
              + ("" if ".30=" in applied else f": {applied[:300]}"))
        # ROADMAP SEC-27: turning the VPN on doesn't move the webUI.
        check("webUI restarting" not in applied,
              "the Apply left the webUI where it was: only the admin moves it (ROADMAP SEC-27)")
        try:  # dropped by the default policy, so this times out
            socket.create_connection((WEBUI_HOST, CLOSED_PORT), timeout=3).recv(1)
        except OSError:
            pass
        time.sleep(5)  # fr-initial-password.path reacts to the account file
        wait_for_webui(opener, boot_timeout)
        # ROADMAP SEC-26: the apply waits for confirmation -- from here,
        # through the new ruleset.
        check("confirm it within 300 s" in applied, "the Apply is held until it is confirmed (ROADMAP SEC-26)")
        check(confirm_pending(opener), "...the dashboard confirms it, and the router keeps it")
        # Security-lessons K5, ROADMAP SEC-27: the admin puts the webUI on
        # the VPN's tunnel address too -- its own action, held as well.
        moved = urllib.parse.unquote_plus(post(opener, "/system/management-addresses",
                                               {"addresses": [WEBUI_HOST, VPN_ADDRESS]}))
        check("confirm it within 300 s" in moved,
              "the webUI address setting applies the move, held until confirmed" + ("" if "confirm" in moved
                                                                                     else f": {moved[:300]}"))
        # The webUI is back from its rebind -- the restarted process, the
        # one on the VPN's address too; the filter below drops the
        # ClientHello naming the blocked name, and only that one.
        check(wait_for_rebind(boot_timeout), f"the restarted webUI answers on the VPN's address {VPN_ADDRESS} "
              "(security-lessons K5)")
        wait_for_webui(opener, boot_timeout)
        check(confirm_pending(opener), "...and is confirmed from the dashboard")
        allowed = any(tls_handshake(XDP_ALLOWED_NAME) for _ in range(3))
        check(allowed, "a TLS handshake naming an allowed host gets through the XDP filter")
        check(allowed and not tls_handshake(XDP_BLOCKED_NAME),
              "the XDP filter drops the ClientHello naming a blocked host (ROADMAP P4-1)")
        # ROADMAP SEC-17: a browser-sized hello, its name in the second
        # segment -- followed by the image's second XDP program.
        split_allowed = split_hello_answered(XDP_ALLOWED_NAME)
        check(split_allowed, "a split ClientHello naming an allowed host gets an answer")
        check(split_allowed and not split_hello_answered(XDP_BLOCKED_NAME),
              "the XDP filter stops a split ClientHello naming a blocked host (ROADMAP SEC-17)")
        # ROADMAP SEC-1: QUIC hides the name, so while the filter is on the
        # router refuses UDP/443 from its port -- and only that port.
        quic, other = udp_through_router(443), udp_through_router(4443)
        check(quic == "refused" and other != "refused",
              f"the router refuses QUIC from the filtered LAN port (ROADMAP SEC-1): UDP/443 {quic}, UDP/4443 {other}")
        # The screen's counters come through the apply-helper: bpffs is
        # root's, and reading them in the webUI was an HTTP 500.
        drops = re.search(r"Drops \(since last load\)</dt>\s*<dd>(\d+)</dd>", get(opener, "/xdp"))
        check(drops is not None and int(drops.group(1)) >= 1,
              "the XDP screen shows the drops, read through the apply-helper (ROADMAP P4-1)"
              + (f": {drops.group(1)}" if drops else ""))
        # ROADMAP SEC-6: a ZTNA sign-in from the host (directly on the LAN
        # port) is bound to the MAC the router sees it at -- the tap's --
        # and the status page reads it back from the kernel's set.
        get(opener, "/ztna/login")
        post(opener, "/ztna/login", {"username": ZTNA_USERNAME, "password": ZTNA_PASSWORD})
        tap_mac = Path(f"/sys/class/net/{LAN_TAP}/address").read_text().strip()
        status_page = getattr(opener, "last_page", "")
        bound = re.search(r'id="ztna-bound">(.*?)</dd>', status_page, re.S)
        check(bound is not None and tap_mac in bound.group(1) and "badge-green" in status_page,
              f"a ZTNA sign-in is bound to the signing-in device's MAC, {tap_mac} (ROADMAP SEC-6)"
              + ("" if bound else ": " + " ".join(status_page.split())[:300]))
        # ROADMAP SEC-27: a LAN address change that would take the webUI's
        # address away is refused when it is saved.
        refused_move = urllib.parse.unquote_plus(post(opener, "/interfaces/save", {
            "name": "lan", "device": "ens4", "zone": "lan", "address": f"{MOVED_LAN_ADDRESS}/24"}))
        check("System -> webUI address" in refused_move,
              "changing the LAN address under the webUI is refused: only the admin moves it (ROADMAP SEC-27)")
        # ROADMAP SEC-26: a move nobody confirms -- the webUI on the VPN's
        # address alone, which this host can't reach -- goes back by
        # itself at its deadline: the webUI answers at the LAN address
        # again, and says the apply was reverted.
        try:
            post(opener, "/system/management-addresses", {"addresses": [VPN_ADDRESS]})
        except OSError:
            pass  # the webUI restarts a few seconds after it answers
        gone = wait_until_unreachable(WEBUI_HOST, 60)
        check(gone, f"...the webUI left {WEBUI_HOST} for the VPN's address alone")
        back = gone and wait_for_webui(opener, 300 + boot_timeout) is not None
        check(back, f"...and, unconfirmed, went back to {WEBUI_HOST} by itself (fr-apply-revert.service)")
        if back:
            dashboard = get(opener, "/")
            check("An apply was not confirmed" in dashboard and "Load it to fix it" in dashboard,
                  "...and the dashboard says so, with the unconfirmed config kept")
        # ROADMAP SEC-5: a config that can't be applied on this machine (a
        # device it doesn't have) changes nothing -- the ZTNA session in the
        # running ruleset is still there. It stays saved for boot 4.
        post(opener, "/interfaces/save", {"name": "spare", "device": SPARE_DEVICE, "zone": "spare",
                                          "address": SPARE_ADDRESS})
        refused = urllib.parse.unquote_plus(post(opener, "/apply", {}))
        check(f"Nothing was applied -- network devices: no such network device on this machine: {SPARE_DEVICE}"
              in refused and "badge-green" in get(opener, "/ztna/status"),
              "an apply the preflight refuses changes nothing on the running router (ROADMAP SEC-5)"
              + ("" if "Nothing was applied" in refused else f": {refused[:300]}"))
    check(vm.power_off(), "powered off")
    vm.kill()
    with persistence_partition(disk) as upper:
        if applied.startswith("POST /apply: HTTP"):
            print_journal(upper, "fr-apply-helper.service", "-b")
        check_sensor_isolation(check, upper, secret=metrics_digest)
        this_boot = journal(upper, "-b", "-u", "fr-first-boot.service")
        check("running initial setup" not in this_boot, "fr-first-boot did not run again")
        check(not (upper / "etc" / "issue.d" / "fr_os-initial-admin.issue").exists()
              and password not in (upper / "etc" / "issue").read_text(),
              "once changed in the webUI, the initial password is gone from the console")
        config = (upper / "etc" / "fr_os" / "config.yaml").read_text()
        check("Europe/Budapest" in config, "a change made in the webUI was saved to the persistence partition")
        check_sandboxed_services(check, upper, "-b")
        dropped_events = xdp_blocked_events(upper)
        check(any('"action": "drop"' in line for line in dropped_events),
              "the dropped ClientHello is in the XDP SNI event file (ROADMAP P4-1, SEC-4)")
        check("Server listening" not in journal(upper, "-b", "-u", "ssh.service"),
              "sshd did not listen at all this boot (off while nobody has a key)")
        # ROADMAP SEC-18: Debian's nftables.service would load
        # /etc/nftables.conf (`flush ruleset`) over the FR_OS ruleset.
        with image_root(args.iso) as root:
            check(nftables_unit_masked(root, upper),
                  "Debian's nftables.service is masked, and persistence didn't unmask it")
        check(not journal(upper, "-u", "nftables.service").strip(), "...and it never ran, on any boot")
        audit_log = upper / "var" / "log" / "fr_os" / "audit.log"
        check(audit_log.exists() and audit_log.stat().st_uid == 0 and audit_log.stat().st_mode & 0o777 == 0o640
              and '"via": "webui"' in audit_log.read_text(),
              "the webUI's audit entries went through the apply-helper into the root-owned log (0640)")
        key = upper / "etc" / "fr_os" / "wireguard" / "private.key"
        check(key.exists() and key.stat().st_uid == 0 and key.stat().st_mode & 0o777 == 0o600
              and key.parent.stat().st_mode & 0o777 == 0o700
              and key.read_text().strip() not in (upper / "etc" / "fr_os" / "config.yaml").read_text(),
              "the router's WireGuard key is root's (0600, 0700 directory) and not in config.yaml")
        check("WireGuard VPN turned on" in audit_log.read_text() and "new VPN device 'laptop'" in audit_log.read_text(),
              "turning the VPN on and adding a device are security alerts")
        dropped = journal(upper, "-b", "-k", "--grep", "fr_os/drop/input")
        check("DPT=4444" in dropped, "a packet the default policy dropped was logged (security-lessons K6)")
        timer = journal(upper, "-b", "-u", "fr-update-check.timer")
        check("Started" in timer, "the periodic update check (fr-update-check.timer) is armed (security-lessons G10)")
        check("IPv4 forwarding" in journal(upper, "-b", "-u", "fr-firewall.service"),
              "the boot-time apply turned IPv4 forwarding on (the router routes)")
        reverted = journal(upper, "-b", "-u", "fr-apply-revert.service")
        check("was not confirmed (no confirmation within 300 s)" in reverted,
              "fr-apply-revert.service reverted the unconfirmed apply in its sandbox (ROADMAP SEC-26)")
        if "was not confirmed" not in reverted:
            print_journal(upper, "fr-apply-revert.service", "-b")
        check("was not confirmed" in audit_log.read_text(), "...and that is a security alert")
        rejected = upper / "etc" / "fr_os" / "config.rejected.yaml"
        kept = re.search(r"^  addresses:\n((?:  - .*\n)+)", rejected.read_text(), re.M) if rejected.exists() else None
        check(kept is not None and kept.group(1).split() == ["-", VPN_ADDRESS],
              "...which kept the unconfirmed config for the admin")

    # ROADMAP SEC-15: the stick, checked from "another computer" -- the
    # host -- with this checkout's keys: clean; then an implant is planted
    # on the persistence partition, which the check must find, and which
    # the router's own check must find in boot 4.
    if signed_build:
        clean_medium = verify_medium(disk)
        check(clean_medium.get("checked", 0) > 100 and not clean_medium.get("modified")
              and not clean_medium.get("missing") and not clean_medium.get("added"),
              f"the stick verifies against the signed release from another computer (ROADMAP SEC-15): "
              f"{clean_medium.get('error') or str(clean_medium.get('checked')) + ' files'}")
        with persistence_partition(disk, writable=True) as upper:
            implant = upper / IMPLANT
            implant.parent.mkdir(parents=True, exist_ok=True)
            implant.write_text("import os  # stands in for an attacker's module\n")
        tampered = verify_medium(disk)
        check(tampered.get("added") == ["/" + IMPLANT],
              f"...and finds the module planted on it (ROADMAP SEC-15): {tampered.get('added') or tampered}")

    # ROADMAP SEC-5: config.yaml now names a device this machine doesn't
    # have. The boot falls back to the config last applied in full (boot
    # 3's), says so, and the webUI listens where that config says.
    print("boot 4: config.yaml can't be applied")
    vm = Vm(workdir, disk, 4, kvm, uefi)
    opener = webui_opener()
    page = wait_for_webui(opener, boot_timeout)
    check(page is not None, "the webUI is reachable at the LAN address of the last applied config")
    landed = post(opener, "/login", {"username": NEW_USERNAME, "password": NEW_PASSWORD}) if page else ""
    check(landed.endswith("/"), "...and the account from boot 3 signs in")
    if signed_build and landed:
        system_page = get(opener, "/system")
        check("badge-red" in system_page and IMPLANT.rsplit("/", 1)[1] in system_page,
              "the router's own check finds the planted module too, and says the software changed (ROADMAP SEC-15)")
    check(vm.power_off(), "powered off")
    vm.kill()
    with persistence_partition(disk) as upper:
        firewall = journal(upper, "-b", "-u", "fr-firewall.service")
        check("WARNING: config.yaml could not be applied at boot, so the router runs the last config" in firewall
              and SPARE_DEVICE in firewall and "WireGuard up" in firewall,
              "config.yaml failed at boot, and the router came up with the last config applied in full (ROADMAP SEC-5)")
        if "WARNING" not in firewall:
            print_journal(upper, "fr-firewall.service", "-b")
        audit_log = upper / "var" / "log" / "fr_os" / "audit.log"
        check("runs the last config that was applied in full" in audit_log.read_text(),
              "...and that is a security alert in the audit log")
        listening = re.findall(r"fr-webui: listening on (.*) port", journal(upper, "-b", "-u", "fr-webui.service"))
        check(bool(listening) and "192.168.1.1" in listening[-1] and SPARE_ADDRESS.split("/")[0] not in listening[-1],
              "the webUI listens on the applied config's addresses, not config.yaml's (ROADMAP SEC-5)"
              + (f": {listening[-1]}" if listening else ""))
        failed = sorted(set(re.findall(r"Failed to start (\S+)", journal(upper, "-b"))))
        check(not failed, f"no unit failed to start{': ' + ', '.join(failed) if failed else ''}")

    run_kernel_trials(check, workdir, disk, Path(args.iso), kvm, uefi, boot_timeout)
    run_kernel_update_from_the_webui(check, workdir, disk, Path(args.iso), kvm, uefi, boot_timeout)

    print()
    if check.failures:
        print(f"{len(check.failures)} check(s) failed; logs in {workdir}")
        return 1
    print(f"all checks passed; logs in {workdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
