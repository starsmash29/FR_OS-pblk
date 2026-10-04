#!/usr/bin/env python3
"""Boot the FR_OS ISO in QEMU the way a user would, three times, and check
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
   password is gone from the console.

Between boots the persistence partition is mounted on the host to read the
journal and files, so a failure says what went wrong. Needs root (losetup,
mount), qemu-system-x86_64 and curl. Takes a few minutes with KVM, ~15
without (TCG). Exit status 0 = every check passed.
"""

from __future__ import annotations

import argparse
import base64
import http.cookiejar
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
BEYOND_NET = "198.51.100.0/24"
BEYOND_HOST = "198.51.100.7"
NEW_PASSWORD = "changed-in-boot-3"
NEW_USERNAME = "netadmin"
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
            # The LAN port: the host's tap, no DHCP server on it -- QEMU's
            # user network always runs one, which would make both ports
            # look like an upstream (ROADMAP SEC-8).
            "-netdev", f"tap,id=lan,ifname={LAN_TAP},script=no,downscript=no",
            "-device", "virtio-net-pci,netdev=lan,mac=52:54:00:00:00:02",
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
def lan_tap():
    """The host's side of the VM's LAN port, for every boot."""
    subprocess.run(["ip", "link", "del", LAN_TAP], capture_output=True)
    subprocess.run(["ip", "tuntap", "add", "dev", LAN_TAP, "mode", "tap"], check=True)
    try:
        subprocess.run(["ip", "addr", "add", LAN_TAP_ADDRESS, "dev", LAN_TAP], check=True)
        subprocess.run(["ip", "link", "set", LAN_TAP, "up"], check=True)
        subprocess.run(["ip", "route", "add", BEYOND_NET, "via", WEBUI_HOST, "dev", LAN_TAP], check=True)
        yield
    finally:
        subprocess.run(["ip", "link", "del", LAN_TAP], capture_output=True)


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


def group_id(upper: Path, name: str) -> int | None:
    """A group's id, from the router's own /etc/group (FR_OS creates its
    accounts at boot, so the file is on the persistence layer)."""
    group_file = upper / "etc" / "group"
    for line in group_file.read_text().splitlines() if group_file.exists() else []:
        fields = line.split(":")
        if len(fields) >= 3 and fields[0] == name:
            return int(fields[2])
    return None


def check_sni_event_file(check, upper: Path) -> None:
    """ROADMAP SEC-4: fr-xdp-sni-logger's event file, which the webUI and
    the sensor daemons read instead of the journal, is root's and
    readable by the fr_os-webui group only -- no reader can write it."""
    directory = upper / "var" / "log" / "fr_os-sni"
    events = directory / "events.jsonl"
    webui_gid = group_id(upper, "fr_os-webui")
    ok = (events.exists() and webui_gid is not None
          and events.stat().st_uid == 0 and events.stat().st_gid == webui_gid
          and events.stat().st_mode & 0o777 == 0o640
          and directory.stat().st_uid == 0 and directory.stat().st_gid == webui_gid
          and directory.stat().st_mode & 0o777 == 0o750)
    detail = ""
    if not ok and events.exists():
        st = events.stat()
        detail = f": {st.st_uid}:{st.st_gid} {oct(st.st_mode & 0o777)} (fr_os-webui is {webui_gid})"
    check(ok, "the XDP SNI event file is root:fr_os-webui 0640 (ROADMAP SEC-4)" + detail)


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
    session's CSRF token -- and return the URL it lands on."""
    token = getattr(opener, "csrf_token", "")
    if token:
        fields = {**fields, "csrf_token": token}
    data = urllib.parse.urlencode(fields, doseq=True).encode()
    with opener.open(f"https://{WEBUI_HOST}:{WEBUI_PORT}{path}", data=data, timeout=30) as resp:
        _remember_csrf(opener, resp.read().decode())
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
    with lan_tap():
        return run(args)


def run(args: argparse.Namespace) -> int:
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
    vm = Vm(workdir, disk, 3, kvm)
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
    if set_up:
        # Security-lessons K7: a fresh FR_OS listens on nothing its config
        # doesn't need.
        surface_page = get(opener, "/surface")
        clean = 'class="flash-success" id="unneeded"' in surface_page
        found = re.search(r'id="unneeded">(.*?)</div>', surface_page, re.S)
        check(clean, "nothing listens that the config doesn't need (security-lessons K7)"
              + ("" if clean else ": " + " ".join((found.group(1) if found else surface_page[:300]).split())))
        # ROADMAP SEC-4: the webUI has no journal access any more; its
        # live XDP log reads the logger's event file from its sandbox.
        first = first_stream_line(opener)
        check(first.startswith((":", "data: {")) and '"error"' not in first,
              "the webUI's live XDP log stream works without journal access (ROADMAP SEC-4)"
              + ("" if '"error"' not in first and first else f": {first.strip()[:200]!r}"))
        score_page = get(opener, "/security")
        score = re.search(r'id="score">(\d+)%', score_page)
        check(score is not None, "the security score page works on the real router (security-lessons K8)"
              + (f": {score.group(1)}%" if score else ""))
        post(opener, "/rules/timezone", {"timezone": "Europe/Budapest"})
        # Security-lessons G8: the WireGuard VPN on Debian's own kernel
        # module (the unit tests use the userspace implementation).
        post(opener, "/vpn/settings", {"enabled": "true", "address": "10.99.0.1/24", "listen_port": "51820",
                                       "endpoint": "vpn.example.net"})
        # Security-lessons K4: the segments offered after setup, on real
        # VLAN devices (802.1Q on the LAN port).
        post(opener, "/segments", {"segment": ["iot", "guest"]})
        device_key = base64.b64encode(os.urandom(32)).decode()
        post(opener, "/vpn/peers/add", {"name": "laptop", "public_key": device_key})
        # ROADMAP P4-1: the XDP SNI filter, on the image's own compiled
        # program, on the LAN port.
        post(opener, "/xdp/settings", {"enabled": "true", "interfaces": ["lan"], "blocklist": XDP_BLOCKED_NAME})
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
        listen = re.search(r"webUI restarting to listen on ([0-9., ]+)", applied)
        check(listen is not None and "10.99.0.1" in listen.group(1),
              "the webUI also listens on the VPN's tunnel address (security-lessons K5)")
        try:  # dropped by the default policy, so this times out
            socket.create_connection((WEBUI_HOST, CLOSED_PORT), timeout=3).recv(1)
        except OSError:
            pass
        time.sleep(5)  # fr-initial-password.path reacts to the account file
        # The webUI is back from its rebind; the filter drops the
        # ClientHello naming the blocked name, and only that one.
        wait_for_webui(opener, boot_timeout)
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
    check(vm.power_off(), "powered off")
    vm.kill()
    with persistence_partition(disk) as upper:
        if applied.startswith("POST /apply: HTTP"):
            print_journal(upper, "fr-apply-helper.service", "-b")
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

    print()
    if check.failures:
        print(f"{len(check.failures)} check(s) failed; logs in {workdir}")
        return 1
    print(f"all checks passed; logs in {workdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
