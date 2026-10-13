#!/usr/bin/env python3
"""Boot the FR_OS ISO in QEMU the way a user would, ten times, and check
that it actually works and remembers what it was told.

    sudo installer/qemu-boot-test.py installer/live-build/binary.hybrid.iso

The ISO is written to a 2 GiB disk image (standing in for a USB stick)
attached to a VM with two NICs -- WAN on QEMU's user network, which has a
DHCP server like an upstream modem, and LAN on a tap device on the host
(10.73.1.2/24), which has none, like a laptop. First boot has to tell
them apart by that (ROADMAP SEC-8); the host reaches the webUI at
https://10.73.1.1/ over the tap, as a LAN client does. The upstream is
192.168.1.0/24 with its router at .1, like most home routers and ISP
boxes: the LAN must stay out of its way (ROADMAP NET-12).

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
   back by itself at the deadline. IPv6 is turned on against a test
   provider (ROADMAP FND-1): the router's WAN and LAN addresses, the LAN
   host's, its stable (ULA) address and DNS over IPv6, management over
   IPv6 on and off again, and the admin's pinhole. A rule by IPv6
   address holds, and a ZTNA sign-in over IPv6 opens the port it gates
   for the whole device (ROADMAP FND-1d). At its end the AI IDS is turned
   on, and a config is saved that names a device the VM doesn't have;
   its apply changes nothing.
4. Fourth boot: config.yaml can't be applied (that device), so the router
   comes up with the config last applied in full, says so, raises a
   security alert, and the webUI is reachable (ROADMAP SEC-5). The AI
   IDS, started at boot, quarantines a LAN host scanning over IPv6 by
   its MAC (ROADMAP FND-1d).
5. Fifth to eighth boot: a kernel staged on the persistence partition
   (ROADMAP SEC-14) -- the image's own, copied there by
   frfw.kernel_boot.stage() from the host, as the router would. Boot 5
   tries it and keeps it (the router came up on it); the hardware
   watchdog (QEMU's i6300esb) is in use. Boot 6 tries it again with the
   webUI masked and the LAN port taken down: the check at the end of the
   boot fails for both, and the router reboots by itself into ... boot
   7, the image's own kernel, which
   raises a security alert. Boot 8 tries one whose initrd is broken: the
   kernel panics and reboots (panic=10), and GRUB has recorded the try.
6. Ninth and tenth boot: the Update screen's kernel card (ROADMAP SEC-14,
   step 3). "Check now" runs fr-kernel-prepare on the router -- pointed
   at the running kernel by a drop-in, so no Debian download is needed:
   the router makes the initrd from the image's own -- and the
   kernel is "ready to try"; "Try it" reboots the router into its trial,
   and boot 10 comes up on the router-built initrd and confirms it,
   checked against what worked when "Try it" was pressed (ROADMAP SEC-23).

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
import html
import http.client
import http.cookiejar
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import stat
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
from frfw import integrity, kernel_boot, system_files  # noqa: E402

#: The router's LAN address, reached over the host's tap device.
WEBUI_HOST = "10.73.1.1"
WEBUI_PORT = 443
#: A LAN port nothing allows: the default policy drops it, and the drop
#: must be logged (security-lessons K6).
CLOSED_PORT = 4444
#: The host's side of the VM's LAN port: a "laptop" with no DHCP server.
LAN_TAP = "frtap0"
LAN_TAP_ADDRESS = "10.73.1.2/24"
#: QEMU's user network, the WAN's upstream: a home router's (ROADMAP
#: NET-12) -- the LAN used to be in this very network.
UPSTREAM_NET = "192.168.1.0/24"
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
MOVED_LAN_ADDRESS = "10.73.1.3"
SPARE_DEVICE = "ens9"
SPARE_ADDRESS = "10.250.0.1/24"
#: ROADMAP FND-1a: the WAN's IPv6 provider. The VM's WAN port is on a
#: QEMU hub with the user network (IPv4, its IPv6 off) and the tap
#: WAN_TAP, which `tc` wires to a veth in the network namespace ISP_NS:
#: there radvd sends Router Advertisements for ISP_PREFIX and kea-dhcp6
#: hands out addresses and /56 prefixes from PD_POOL, as a provider does.
#: The host's own network stack takes no part.
ISP_NS = "fr-isp"
WAN_TAP = "frwan0"
ISP_WIRE = "frwanv"
ISP_DEVICE = "isp0"
ISP_ADDRESS = "2001:db8:1::1"
ISP_PREFIX = "2001:db8:1::/64"
PD_POOL = "2001:db8:100::/48"
#: What a forged Router Advertisement from the WAN's link offers: one sent
#: with a hop limit below 255 has crossed a router (RFC 4861).
FORGED_PREFIX = "2001:db8:bad::/64"
#: The router's WAN port's MAC (in Vm) and the interface identifier
#: (EUI-64) a SLAAC address made from it would end in.
#: A source address outside every network of the router's (BCP 38).
SPOOFED_SOURCE = "2001:db8:bad::5"
#: A TCP port the LAN host listens on, for a connection from the provider.
LAN_HOST_PORT = 8443
#: ROADMAP FND-1c: the admin's pinhole to the LAN host -- by interface ID,
#: an address the host is given by hand in whatever /64 the LAN has, and
#: one port of it. Written into config.yaml before boot 3, the way a
#: pinhole is set in this step (the webUI lists them, it doesn't edit
#: them); kept, unused, while IPv6 is off.
PINHOLE_IID = "::f00d:1"
PINHOLE_PORT = 8444
PINHOLE_YAML = f"""\
ipv6:
  enabled: false
  pinholes:
    - name: boot-test-nas
      zone: lan
      host: "{PINHOLE_IID}"
      proto: tcp
      port: {PINHOLE_PORT}
"""
#: A second LAN host (ROADMAP FND-1d, H3): a macvlan on the LAN tap, so
#: its own MAC, in a namespace of its own.
NEIGHBOUR_NS = "fr-lan2"
NEIGHBOUR_LINK = "frlan2"
#: The interface IDs it adds by hand, as an attacker picking addresses.
JAIL_IIDS = ("::a1", "::a2", "::a3", "::a4", "::a5")
#: ROADMAP FND-1d (1d-3), rules by IPv6 address, on the provider's
#: closed ports (it refuses them, so "refused" means the router let the
#: connection through): a drop rule naming IPv4 and IPv6 destinations
#: holds one port; a ZTNA-gated accept, then a drop, the next one; the
#: third has no rule.
RULE_DROP_PORT = 8445
ZTNA_GATED_PORT = 8446
NO_RULE_PORT = 8447
#: The ports the second LAN host scans (ROADMAP FND-1d), enough new
#: connections in a minute for the AI IDS's connection-rate floor (5/s),
#: at an address beyond the provider, which refuses them at once with an
#: ICMPv6 error. Not at the provider's own closed ports: the kernel drops
#: a connection's conntrack entry the moment a RST answers its SYN, so
#: the IDS's sample never sees those (a known limit, ARCHITECTURE.md).
SCAN_PORTS = range(20000, 21000)
SCAN_TARGET = "2001:db8:dead::1"
#: Those rules, ahead of first boot's lan-to-wan accept: the Rules screen
#: adds a rule at the end, where that accept shadows it. Written into
#: config.yaml before boot 3, like the pinhole.
RULES_V6 = f"""\
- name: boot-test-drop-v6
  action: drop
  from_zone: lan
  to_zone: wan
  proto: tcp
  dst_port: {RULE_DROP_PORT}
  dst_address: ["{BEYOND_HOST}", "{ISP_ADDRESS}"]
- name: boot-test-ztna-v6
  action: accept
  from_zone: lan
  to_zone: wan
  proto: tcp
  dst_port: {ZTNA_GATED_PORT}
  dst_address: "{ISP_ADDRESS}"
  require_ztna: true
- name: boot-test-ztna-v6-closed
  action: drop
  from_zone: lan
  to_zone: wan
  proto: tcp
  dst_port: {ZTNA_GATED_PORT}
  dst_address: "{ISP_ADDRESS}"
"""
#: A WireGuard client (ROADMAP FND-1d, 1d-1): its link is made in the
#: runner's namespace, so its UDP socket reaches the router over the LAN
#: tap, then moved into a namespace of its own, where the tunnel is the
#: only way out, as on a phone with everything sent through the VPN.
VPN_CLIENT_NS = "fr-wg"
VPN_CLIENT_LINK = "frwgc"
WAN_MAC = "52:54:00:00:00:01"
WAN_MAC_IID = "5054:ff:fe00:1"
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
            # The WAN port: a hub joining QEMU's user network (the upstream's
            # IPv4 and DHCP; its own IPv6 off) and the IPv6 provider's tap
            # (ROADMAP FND-1a), like a modem's port with both on it.
            "-netdev", f"user,id=upstream4,ipv6=off,net={UPSTREAM_NET},host=192.168.1.1",
            "-netdev", "hubport,id=wanhub4,hubid=0,netdev=upstream4",
            "-netdev", f"tap,id=upstream6,ifname={WAN_TAP},script=no,downscript=no",
            "-netdev", "hubport,id=wanhub6,hubid=0,netdev=upstream6",
            "-netdev", "hubport,id=wan,hubid=0",
            "-device", f"virtio-net-pci,netdev=wan,mac={WAN_MAC}",
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
    """The host's side of the VM's LAN port, for every boot. Over IPv6 it
    is a LAN host (ROADMAP FND-1b): SLAAC from the router's RAs -- taken
    even with the host's own forwarding on (accept_ra=2), but no default
    route from them: the host's own IPv6 stays as it is."""
    subprocess.run(["ip", "link", "del", LAN_TAP], capture_output=True)
    subprocess.run(["ip", "tuntap", "add", "dev", LAN_TAP, "mode", "tap"], check=True)
    try:
        for key, value in (("disable_ipv6", "0"), ("accept_ra", "2"), ("autoconf", "1"),
                           ("accept_ra_defrtr", "0"), ("use_tempaddr", "0")):
            _sysctl(f"net.ipv6.conf.{LAN_TAP}.{key}", value)
        subprocess.run(["ip", "addr", "add", LAN_TAP_ADDRESS, "dev", LAN_TAP], check=True)
        subprocess.run(["ip", "link", "set", LAN_TAP, "up"], check=True)
        subprocess.run(["ip", "route", "add", BEYOND_NET, "via", WEBUI_HOST, "dev", LAN_TAP], check=True)
        subprocess.run(["ip", "route", "add", f"{VPN_ADDRESS}/32", "via", WEBUI_HOST, "dev", LAN_TAP], check=True)
        yield
    finally:
        subprocess.run(["ip", "link", "del", LAN_TAP], capture_output=True)


def _sysctl(path: str, value: str, ns: str | None = None) -> None:
    cmd = ["sysctl", "-q", "-w", f"{path}={value}"]
    subprocess.run(["ip", "netns", "exec", ns, *cmd] if ns else cmd, check=True)


def isp_run(*cmd: str, timeout: float = 30) -> subprocess.CompletedProcess:
    """A command on the provider's side (its network namespace)."""
    return subprocess.run(["ip", "netns", "exec", ISP_NS, *cmd], capture_output=True, text=True, timeout=timeout)


RADVD_CONF = f"""\
interface {ISP_DEVICE} {{
    AdvSendAdvert on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 10;
    AdvDefaultLifetime 1800;
    # DHCPv6 for the rest (an address of its own and the prefix).
    AdvManagedFlag on;
    AdvOtherConfigFlag on;
    prefix {ISP_PREFIX} {{
        AdvOnLink on;
        AdvAutonomous on;
    }};
}};
"""


def kea6_conf(log: Path) -> dict:
    return {"Dhcp6": {
        "interfaces-config": {"interfaces": [ISP_DEVICE]},
        # Nothing written outside the work directory: no DUID file, no
        # lease file.
        "server-id": {"type": "EN", "enterprise-id": 32473, "identifier": "0f05", "persist": False},
        "lease-database": {"type": "memfile", "persist": False},
        "subnet6": [{
            "id": 1, "subnet": ISP_PREFIX, "interface": ISP_DEVICE,
            "pools": [{"pool": "2001:db8:1::1000-2001:db8:1::1fff"}],
            "pd-pools": [{"prefix": PD_POOL.split("/")[0], "prefix-len": int(PD_POOL.split("/")[1]),
                          "delegated-len": 56}],
        }],
        "loggers": [{"name": "kea-dhcp6", "severity": "INFO",
                     "output_options": [{"output": str(log), "flush": True}]},
                    # Every message received, to tell "nothing asked" from
                    # "asked, not answered".
                    {"name": "kea-dhcp6.packets", "severity": "DEBUG", "debuglevel": 40,
                     "output_options": [{"output": str(log), "flush": True}]}],
    }}


#: Where Ubuntu's kea-dhcp6 keeps its log, PID and lock files; the log is
#: copied to the work directory at the end.
KEA_LOG = Path("/var/log/kea/kea-dhcp6-fr-os-boot-test.log")
KEA_RUN_DIR = Path("/run/kea")
#: Ubuntu's AppArmor profile for kea-dhcp6 (the CI runner's): it allows
#: only the packaged service's paths, and this one is no service.
KEA_APPARMOR = Path("/etc/apparmor.d/usr.sbin.kea-dhcp6")


class Isp:
    def __init__(self, workdir: Path) -> None:
        self.kea_log = KEA_LOG
        self.radvd_log = workdir / "radvd.log"

    def leases(self) -> str:
        """What kea-dhcp6 handed out: an address and a prefix per lease."""
        try:
            text = self.kea_log.read_text(errors="replace")
        except OSError:
            return ""
        return "\n".join(l for l in text.splitlines() if "LEASE_ALLOC" in l)

    def print_logs(self) -> None:
        # What crossed the wire to and from the router, and who the
        # provider's side has seen.
        for cmd in (["ip", "-s", "link", "show", ISP_DEVICE], ["ip", "-6", "neigh", "show"]):
            print(f"    --- {' '.join(cmd)} ---")
            for line in isp_run(*cmd).stdout.splitlines():
                print(f"    {line}")
        for log in (self.kea_log, self.radvd_log):
            print(f"    --- {log.name} ---")
            try:
                for line in log.read_text(errors="replace").splitlines()[-25:]:
                    print(f"    {line}")
            except OSError:
                print("    (none)")


def _remove_isp() -> None:
    subprocess.run(["ip", "netns", "del", ISP_NS], capture_output=True)
    for device in (WAN_TAP, ISP_WIRE):
        subprocess.run(["ip", "link", "del", device], capture_output=True)


@contextmanager
def isp(workdir: Path):
    """The WAN's IPv6 provider (ROADMAP FND-1a), for every boot: radvd and
    kea-dhcp6 in a network namespace of their own, wired to the VM's WAN
    tap by `tc` -- not a bridge, so neither the host's stack nor its
    firewall (Docker's, on a CI runner) sees the frames. The namespace
    routes nothing: its default route is unreachable, so what the router
    sends towards the internet over IPv6 is refused at once, not lost."""
    _remove_isp()
    procs: list[subprocess.Popen] = []
    # The packaged services, started by apt, stay out of it.
    for unit in ("radvd", "kea-dhcp6-server"):
        subprocess.run(["systemctl", "stop", unit], capture_output=True)
    try:
        subprocess.run(["ip", "netns", "add", ISP_NS], check=True)
        subprocess.run(["ip", "tuntap", "add", "dev", WAN_TAP, "mode", "tap"], check=True)
        subprocess.run(["ip", "link", "add", ISP_WIRE, "type", "veth", "peer", "name", ISP_DEVICE,
                        "netns", ISP_NS], check=True)
        for device in (WAN_TAP, ISP_WIRE):
            _sysctl(f"net.ipv6.conf.{device}.disable_ipv6", "1")
            subprocess.run(["ip", "link", "set", device, "up"], check=True)
            other = ISP_WIRE if device == WAN_TAP else WAN_TAP
            subprocess.run(["tc", "qdisc", "add", "dev", device, "ingress"], check=True)
            subprocess.run(["tc", "filter", "add", "dev", device, "parent", "ffff:", "matchall",
                            "action", "mirred", "egress", "redirect", "dev", other], check=True)
        _sysctl("net.ipv6.conf.all.forwarding", "1", ISP_NS)
        for cmd in (["ip", "link", "set", "lo", "up"], ["ip", "link", "set", ISP_DEVICE, "up"],
                    ["ip", "-6", "addr", "add", f"{ISP_ADDRESS}/64", "dev", ISP_DEVICE],
                    ["ip", "-6", "route", "add", "unreachable", "default"]):
            subprocess.run(["ip", "netns", "exec", ISP_NS, *cmd], check=True)
        deadline = time.monotonic() + 30  # duplicate address detection
        while time.monotonic() < deadline and "tentative" in isp_run("ip", "-6", "addr", "show", "dev",
                                                                     ISP_DEVICE).stdout:
            time.sleep(0.5)
        provider = Isp(workdir)
        radvd_conf = workdir / "radvd.conf"
        radvd_conf.write_text(RADVD_CONF)
        kea_conf = workdir / "kea-dhcp6.json"
        kea_conf.write_text(json.dumps(kea6_conf(provider.kea_log), indent=2))
        if KEA_APPARMOR.exists():
            subprocess.run(["apparmor_parser", "-R", str(KEA_APPARMOR)], capture_output=True)
        KEA_LOG.parent.mkdir(parents=True, exist_ok=True)
        KEA_LOG.unlink(missing_ok=True)
        KEA_RUN_DIR.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "KEA_LOCKFILE_DIR": str(KEA_RUN_DIR), "KEA_PIDFILE_DIR": str(KEA_RUN_DIR)}
        with provider.radvd_log.open("w") as radvd_out:
            procs.append(subprocess.Popen(
                ["ip", "netns", "exec", ISP_NS, "radvd", "--nodaemon", "--logmethod", "stderr",
                 "--config", str(radvd_conf), "--pidfile", str(workdir / "radvd.pid")],
                stdout=radvd_out, stderr=subprocess.STDOUT))
        with (workdir / "kea-dhcp6.out").open("w") as kea_out:
            procs.append(subprocess.Popen(["ip", "netns", "exec", ISP_NS, "kea-dhcp6", "-c", str(kea_conf)],
                                          stdout=kea_out, stderr=subprocess.STDOUT, env=env))
        time.sleep(2)
        for proc in procs:
            if proc.poll() is not None:
                provider.print_logs()
                print((workdir / "kea-dhcp6.out").read_text(errors="replace"))
                raise RuntimeError(f"the IPv6 provider's {proc.args[4]} exited ({proc.returncode})")
        yield provider
    finally:
        for proc in procs:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        if KEA_LOG.exists():
            shutil.copyfile(KEA_LOG, workdir / "kea-dhcp6.log")
        _remove_isp()


def ping_sources(target: str) -> set[str]:
    """Who answers a ping to `target` from the provider's side, the
    provider's own addresses left out."""
    out = isp_run("ping", "-6", "-n", "-c", "3", "-i", "0.5", "-w", "4", target).stdout
    own = set(re.findall(r"inet6 ([0-9a-f:]+)/", isp_run("ip", "-6", "-o", "addr", "show").stdout))
    return set(re.findall(r"from ([0-9a-f:]+)(?:%\S+)?: icmp_seq", out)) - own


def tcp_from_isp(address: str, port: int) -> str:
    """'open', 'refused' or 'no answer' for a TCP connection from the
    provider's side to the router."""
    code = ("import socket,sys\n"
            "try:\n"
            f"    socket.create_connection(({address!r}, {port}), timeout=4).close(); print('open')\n"
            "except ConnectionRefusedError: print('refused')\n"
            "except OSError: print('no answer')\n")
    return isp_run("python3", "-I", "-c", code).stdout.strip() or "error"


def forge_router_advert(prefix: str, hop_limit: int) -> None:
    """A Router Advertisement for `prefix` from the provider's link, sent
    with `hop_limit` (an RA that crossed a router has less than 255)."""
    network = ipaddress.IPv6Network(prefix)
    # Type 134, code 0, checksum (the kernel's), current hop limit 64, no
    # flags, router lifetime 1800 s, reachable time, retransmit timer;
    # then a Prefix Information option, on-link and autonomous.
    ra = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, 1800, 0, 0)
    ra += struct.pack("!BBBBIII", 3, 4, network.prefixlen, 0xC0, 86400, 14400, 0) + network.network_address.packed
    code = ("import socket,sys\n"
            "s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)\n"
            f"s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, {hop_limit})\n"
            f"s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, socket.if_nametoindex({ISP_DEVICE!r}))\n"
            f"for _ in range(3): s.sendto(bytes.fromhex({ra.hex()!r}), ('ff02::1', 0, 0, "
            f"socket.if_nametoindex({ISP_DEVICE!r})))\n")
    isp_run("python3", "-I", "-c", code)


def ipv6_card(opener) -> tuple[str, list[str], list[str]]:
    """The Interfaces screen's IPv6 card: its state, the WAN's addresses
    and the delegated prefixes."""
    page = get(opener, "/interfaces")
    state = re.search(r'id="ipv6-summary" data-state="([^"]*)"', page)
    return (state.group(1) if state else "",
            re.findall(r'<dd class="ipv6-address">([^<]*)</dd>', page),
            re.findall(r'<dd class="ipv6-prefix">([^<]*)</dd>', page))


def ipv6_card_stable(opener) -> tuple[dict[str, str], dict[str, str]]:
    """The card's stable (ULA) addresses of the router, "zone (device)" ->
    address, and its pinholes, name -> where they lead (ROADMAP FND-1c)."""
    page = get(opener, "/interfaces")
    return (dict(re.findall(r'<dt>([^<]*), stable</dt><dd class="ipv6-ula">([^<]*)</dd>', page)),
            {k: html.unescape(v) for k, v in
             re.findall(r'<dt>Pinhole ([^<]*)</dt><dd class="ipv6-pinhole">([^<]*)</dd>', page)})


def router_advert(timeout: float = 15) -> tuple[list[ipaddress.IPv6Network], list[str]] | None:
    """The router's Router Advertisement on the LAN, solicited: the
    prefixes it advertises (Prefix Information) and the DNS servers
    (RDNSS, RFC 8106) -- or None when none came."""
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, LAN_TAP.encode())
        s.settimeout(1)
        solicit_router()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data = s.recv(4096)
            except OSError:
                continue
            if data and data[0] == 134:
                return parse_router_advert(data)
        return None
    finally:
        s.close()


def parse_router_advert(data: bytes) -> tuple[list[ipaddress.IPv6Network], list[str]]:
    """A Router Advertisement's prefixes (Prefix Information, RFC 4861
    4.6.2) and DNS servers (RDNSS, RFC 8106 5.1)."""
    prefixes, servers, offset = [], [], 16  # past the RA's fixed part
    while offset + 8 <= len(data) and data[offset + 1]:
        kind, length = data[offset], data[offset + 1] * 8
        body = data[offset:offset + length]
        if kind == 3 and length == 32:
            prefixes.append(ipaddress.IPv6Network((bytes(body[16:32]), body[2]), strict=False))
        elif kind == 25:
            servers += [str(ipaddress.IPv6Address(bytes(body[i:i + 16]))) for i in range(8, length - 15, 16)]
        offset += length
    return prefixes, servers


def ipv6_card_lan(opener) -> tuple[str, dict[str, str]]:
    """The card's summary, and its LAN networks: "zone (device)" -> network."""
    page = get(opener, "/interfaces")
    summary = re.search(r'id="ipv6-summary" data-state="[^"]*">([^<]*)</p>', page)
    return (html.unescape(summary.group(1)) if summary else "",
            dict(re.findall(r'<dt>([^<]*)</dt><dd class="ipv6-lan">([^<]*)</dd>', page)))


def lan_host_addresses() -> list[ipaddress.IPv6Interface]:
    """The host's global IPv6 addresses on the LAN tap, DAD done."""
    out = subprocess.run(["ip", "-j", "-6", "addr", "show", "dev", LAN_TAP], capture_output=True, text=True).stdout
    found = []
    for link in json.loads(out or "[]"):
        for info in link.get("addr_info", []):
            if info.get("scope") == "global" and not info.get("tentative") and not info.get("dadfailed"):
                found.append(ipaddress.IPv6Interface(f"{info['local']}/{info['prefixlen']}"))
    return found


def solicit_router() -> None:
    """A Router Solicitation from the LAN host (hop limit 255), so the
    router's RA comes at once rather than at its next interval."""
    rs = struct.pack("!BBHI", 133, 0, 0, 0)
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    try:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        index = socket.if_nametoindex(LAN_TAP)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
        s.sendto(rs, ("ff02::2", 0, 0, index))
    finally:
        s.close()


def echo_sources_at_isp(seconds: float) -> subprocess.Popen:
    """Listens in the provider's namespace for `seconds`; its output is
    the source of every ICMPv6 echo request that reached the provider."""
    code = ("import select,socket,time\n"
            "s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)\n"
            f"end, seen = time.time() + {seconds}, set()\n"
            "while time.time() < end:\n"
            "    if select.select([s], [], [], 0.2)[0]:\n"
            "        data, peer = s.recvfrom(2048)\n"
            "        if data and data[0] == 128: seen.add(peer[0])\n"
            "print(' '.join(sorted(seen)))\n")
    return subprocess.Popen(["ip", "netns", "exec", ISP_NS, "python3", "-I", "-c", code],
                            stdout=subprocess.PIPE, text=True)


@contextmanager
def second_lan_host():
    """A second host on the LAN segment, with a MAC of its own: a macvlan
    on the LAN tap in its own namespace, taking SLAAC from the router's
    RAs like the first."""
    subprocess.run(["ip", "netns", "del", NEIGHBOUR_NS], capture_output=True)
    subprocess.run(["ip", "netns", "add", NEIGHBOUR_NS], check=True)
    try:
        subprocess.run(["ip", "link", "add", NEIGHBOUR_LINK, "link", LAN_TAP, "type", "macvlan", "mode", "bridge"],
                       check=True)
        subprocess.run(["ip", "link", "set", NEIGHBOUR_LINK, "netns", NEIGHBOUR_NS], check=True)
        for key, value in (("disable_ipv6", "0"), ("accept_ra", "2"), ("autoconf", "1"), ("use_tempaddr", "0")):
            _sysctl(f"net.ipv6.conf.{NEIGHBOUR_LINK}.{key}", value, NEIGHBOUR_NS)
        for link in ("lo", NEIGHBOUR_LINK):
            subprocess.run(["ip", "netns", "exec", NEIGHBOUR_NS, "ip", "link", "set", link, "up"], check=True)
        yield
    finally:
        subprocess.run(["ip", "netns", "del", NEIGHBOUR_NS], capture_output=True)


#: Run in the second host's namespace: argv is the router's address,
#: then "login" or "tcp", then the sources. Prints one result per source:
#: where a failed sign-in landed, or the TCP connection's outcome.
_NEIGHBOUR_CLIENT = """\
import http.client, json, socket, ssl, sys, urllib.parse
target, what, sources = sys.argv[1], sys.argv[2], sys.argv[3:]
context = ssl.create_default_context(); context.check_hostname = False; context.verify_mode = ssl.CERT_NONE
out = []
for source in sources:
    try:
        if what == "tcp":
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(4)
            s.bind((source, 0)); s.connect((target, 443)); s.close(); out.append("open")
            continue
        c = http.client.HTTPSConnection(target, 443, timeout=20, context=context, source_address=(source, 0))
        c.request("POST", "/login", urllib.parse.urlencode({"username": "intruder", "password": "wrong"}),
                  {"Content-Type": "application/x-www-form-urlencoded"})
        r = c.getresponse(); out.append(urllib.parse.unquote_plus(r.getheader("Location") or str(r.status)))
    except ConnectionRefusedError:
        out.append("refused")
    except OSError as exc:
        out.append("no answer" if what == "tcp" else f"error: {exc}")
print(json.dumps(out))
"""


def from_second_host(target: str, what: str, sources: list[str]) -> list[str]:
    proc = subprocess.run(["ip", "netns", "exec", NEIGHBOUR_NS, "python3", "-I", "-c", _NEIGHBOUR_CLIENT,
                           target, what, *sources], capture_output=True, text=True, timeout=300)
    try:
        return json.loads(proc.stdout)
    except ValueError:
        return [proc.stderr.strip()[-300:]]


def second_host_address(network: ipaddress.IPv6Network, timeout: float = 60) -> str | None:
    """The second host's SLAAC address in `network`, DAD done."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        out = subprocess.run(["ip", "netns", "exec", NEIGHBOUR_NS, "ip", "-j", "-6", "addr", "show", "dev",
                              NEIGHBOUR_LINK], capture_output=True, text=True).stdout
        for link in json.loads(out or "[]"):
            for info in link.get("addr_info", []):
                if info.get("tentative") or info.get("dadfailed"):
                    continue
                if ipaddress.IPv6Address(info["local"]) in network:
                    return info["local"]
        time.sleep(2)
    return None


def check_ipv6_jail(check, ula: str, ula_network: ipaddress.IPv6Network, ula_source: str) -> None:
    """ROADMAP FND-1d (H3), with management over IPv6 on: a second LAN
    host fails to sign in five times, from five addresses of its own
    choosing. Counted as one host (by its MAC), the fifth gets it jailed;
    it is then held on every address, a new one too. The first host, on
    the same /64, still reaches the webUI -- FND-1c's /64 jail held it
    too."""
    with second_lan_host():
        slaac = second_host_address(ula_network)
        if not check(slaac is not None, "a second LAN host (its own MAC) took a stable address by SLAAC"):
            return
        picked = [str(ula_network.network_address + int(ipaddress.IPv6Address(iid))) for iid in JAIL_IIDS]
        for address in picked:
            subprocess.run(["ip", "netns", "exec", NEIGHBOUR_NS, "ip", "addr", "add", f"{address}/64", "dev",
                            NEIGHBOUR_LINK, "nodad"], check=True)
        sources = [slaac, *picked[:4]]
        landed = from_second_host(ula, "login", sources)
        check(len(landed) == 5 and all("Invalid credentials" in x for x in landed[:4])
              and "temporarily blocked" in landed[4],
              f"five failed sign-ins over IPv6 from five addresses of one host count as one host, and the "
              f"fifth jails it: {landed}")
        held = from_second_host(ula, "tcp", [*sources, picked[4]])
        check(set(held) == {"no answer"},
              f"...held by its MAC on every address, and on one it hadn't used yet: {held}")
        neighbour = tcp_from_lan(ula, WEBUI_PORT, ula_source)
        check(neighbour == "open",
              f"...while the other LAN host on the same /64 still reaches the webUI over IPv6: {neighbour}")


def ztna_sign_in_over_ipv6(router: str, source: str) -> str:
    """A ZTNA sign-in from the LAN host, over IPv6 from `source`: where it
    lands. The gate's sign-in needs no session (and so no CSRF token)."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        c = http.client.HTTPSConnection(router, WEBUI_PORT, timeout=30, context=context,
                                        source_address=(source, 0))
        c.request("POST", "/ztna/login", urllib.parse.urlencode({"username": ZTNA_USERNAME,
                                                                 "password": ZTNA_PASSWORD}),
                  {"Content-Type": "application/x-www-form-urlencoded"})
        response = c.getresponse()
        return urllib.parse.unquote_plus(response.getheader("Location") or str(response.status))
    except OSError as exc:
        return f"error: {exc}"


def check_ipv6_rules_and_ztna(check, ula: str, ula_source: str, source: str) -> None:
    """ROADMAP FND-1d (1d-3), with management over IPv6 on: the drop rule
    naming the provider's IPv6 address holds over IPv6 (and, naming IPv6
    too, didn't take the LAN zone off it); the ZTNA-gated port is closed
    until the LAN host signs in over IPv6 -- at its stable address -- and
    then open from its delegated one too: a sign-in admits the device,
    every address its MAC has."""
    ping_from_lan(ISP_ADDRESS, source)  # the router knows the address's MAC
    ports = {port: tcp_from_lan(ISP_ADDRESS, port, source) for port in (RULE_DROP_PORT, NO_RULE_PORT)}
    check(ports == {RULE_DROP_PORT: "no answer", NO_RULE_PORT: "refused"},
          f"a drop rule by IPv6 address holds over IPv6, and only for its port (ROADMAP FND-1d): {ports}")
    before = tcp_from_lan(ISP_ADDRESS, ZTNA_GATED_PORT, source)
    landed = ztna_sign_in_over_ipv6(ula, ula_source)
    after = tcp_from_lan(ISP_ADDRESS, ZTNA_GATED_PORT, source)
    check(before == "no answer" and "/ztna/status" in landed and "access granted" in landed
          and after == "refused",
          f"a ZTNA sign-in over IPv6 at the router's stable address opens the gated port from the device's "
          f"other address too (ROADMAP FND-1d): before {before}, sign-in {landed[:200]}, after {after}")


#: Run in the second host's namespace: argv is the source, the target and
#: the first and last port. Sends each port one SYN, as a fast scanner
#: does, without waiting for the answer: the provider rate-limits its
#: ICMPv6 errors, and waiting for them made the scan too slow to count.
#: A socket closed before an answer sends nothing more, and the router's
#: conntrack entry stays (SYN_SENT). Prints how many SYNs went out.
_SCAN = """\
import socket, sys
source, target, first, last = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
sent = 0
for port in range(first, last + 1):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.setblocking(False)
    s.bind((source, 0))
    sent += s.connect_ex((target, port)) in (0, 115)  # EINPROGRESS: the SYN is out
    s.close()
print(f"{sent} SYNs sent")
"""


def check_ids_ipv6(check, opener) -> bool:
    """ROADMAP FND-1d (1d-3), in boot 4, with the AI IDS turned on in boot
    3: a second LAN host scans a thousand ports over IPv6 (SCAN_TARGET). The IDS
    scores it by its MAC (the helper labels the conntrack sample) and
    quarantines it by its MAC: held on every address, one it hadn't used
    too, while the first LAN host still gets through."""
    pool = ipaddress.IPv6Network(PD_POOL)
    with second_lan_host():
        address = second_host_address(pool, timeout=180)
        if not check(address is not None, "a second LAN host took a delegated address by SLAAC (boot 4)"):
            return False
        mac_file = f"/sys/class/net/{NEIGHBOUR_LINK}/address"
        mac = subprocess.run(["ip", "netns", "exec", NEIGHBOUR_NS, "cat", mac_file],
                             capture_output=True, text=True).stdout.strip()
        before = from_second_host(ISP_ADDRESS, "tcp", [address])
        scan = subprocess.run(["ip", "netns", "exec", NEIGHBOUR_NS, "python3", "-I", "-c", _SCAN, address,
                               SCAN_TARGET, str(SCAN_PORTS[0]), str(SCAN_PORTS[-1])],
                              capture_output=True, text=True, timeout=600)
        page = ""
        deadline = time.monotonic() + 240  # the IDS scores once a minute
        while time.monotonic() < deadline:
            page = get(opener, "/ai-ids")
            if f"MAC {mac}" in page:
                break
            time.sleep(10)
        held_mac = f"MAC {mac}" in page
        check(before == ["refused"] and held_mac,
              f"the AI IDS quarantines a LAN host scanning over IPv6 by its MAC, {mac} (ROADMAP FND-1d): scan "
              f"{scan.stdout.strip() or scan.stderr[-200:]}, before {before}")
        network = ipaddress.IPv6Interface(f"{address}/64").network
        other = str(network.network_address + int(ipaddress.IPv6Address("::a6")))
        subprocess.run(["ip", "netns", "exec", NEIGHBOUR_NS, "ip", "addr", "add", f"{other}/64", "dev",
                        NEIGHBOUR_LINK, "nodad"], check=True)
        held = from_second_host(ISP_ADDRESS, "tcp", [address, other])
        check(held_mac and held == ["no answer", "no answer"],
              f"...held by its MAC on every address, and on one it hadn't used yet: {held}")
        first = next((a for a in lan_host_addresses() if a.ip in pool), None)
        check(first is not None and ping_from_lan(ISP_ADDRESS, str(first.ip)),
              f"...while the other LAN host still reaches the provider over IPv6: {first}")
        return held_mac


def _client_config_field(text: str, key: str) -> str | None:
    match = re.search(rf"^{key} = (.+)$", text, re.M)
    return match.group(1).strip() if match else None


@contextmanager
def vpn_client(config_text: str):
    """The device's configuration from the webUI, brought up on the
    kernel's WireGuard as the device would: its addresses, and a default
    route for each family into the tunnel. Its endpoint is the router's
    LAN address rather than the configuration's DNS name."""
    subprocess.run(["ip", "netns", "del", VPN_CLIENT_NS], capture_output=True)
    subprocess.run(["ip", "link", "del", VPN_CLIENT_LINK], capture_output=True)
    key_file = tempfile.NamedTemporaryFile("w", prefix="fros-wg-", delete=False)
    try:
        os.chmod(key_file.name, 0o600)
        key_file.write(_client_config_field(config_text, "PrivateKey") + "\n")
        key_file.close()
        subprocess.run(["ip", "netns", "add", VPN_CLIENT_NS], check=True)
        subprocess.run(["ip", "link", "add", VPN_CLIENT_LINK, "type", "wireguard"], check=True)
        subprocess.run(["wg", "set", VPN_CLIENT_LINK, "private-key", key_file.name,
                        "peer", _client_config_field(config_text, "PublicKey"),
                        "endpoint", f"{WEBUI_HOST}:51820", "persistent-keepalive", "5",
                        "allowed-ips", _client_config_field(config_text, "AllowedIPs").replace(" ", "")],
                       check=True)
        subprocess.run(["ip", "link", "set", VPN_CLIENT_LINK, "netns", VPN_CLIENT_NS], check=True)
        inside = ["ip", "netns", "exec", VPN_CLIENT_NS]
        for address in _client_config_field(config_text, "Address").split(","):
            subprocess.run([*inside, "ip", "addr", "add", address.strip(), "dev", VPN_CLIENT_LINK]
                           + (["nodad"] if ":" in address else []), check=True)
        for link in ("lo", VPN_CLIENT_LINK):
            subprocess.run([*inside, "ip", "link", "set", link, "up"], check=True)
        subprocess.run([*inside, "ip", "-4", "route", "add", "default", "dev", VPN_CLIENT_LINK], check=True)
        subprocess.run([*inside, "ip", "-6", "route", "add", "default", "dev", VPN_CLIENT_LINK], check=True)
        yield
    finally:
        subprocess.run(["ip", "netns", "del", VPN_CLIENT_NS], capture_output=True)
        os.unlink(key_file.name)


def check_vpn_ipv6(check, opener, boot_timeout: float) -> None:
    """ROADMAP FND-1d (1d-1, H1): a device added on the VPN screen after
    the router made its ULA prefix gets an IPv6 address in the tunnel,
    and its full-tunnel configuration sends IPv6 into the tunnel too
    (::/0) -- not around it, in the clear. The router answers the
    device's ping over IPv6 and routes its IPv6 to the LAN's stable (ULA)
    addresses (the LAN keeps its IPv6 with the SNI filter on since 1d-2),
    and refuses the rest at once, rather than dropping it, so the device's
    apps fall back to IPv4 for the internet."""
    post(opener, "/vpn/peers/add", {"name": "phone", "full_tunnel": "true"})
    page = html.unescape(opener.last_page)
    config_text = re.search(r"<pre>(.*?)</pre>", page, re.S)
    config_text = config_text.group(1) if config_text else ""
    address = _client_config_field(config_text, "Address") or ""
    v6 = [a.strip() for a in address.split(",") if ":" in a]
    allowed = _client_config_field(config_text, "AllowedIPs")
    # Never the configuration itself in the log: it holds the device's
    # private key (the log is public).
    if not check(allowed == "0.0.0.0/0, ::/0" and len(v6) == 1 and ":ffff::" in v6[0],
                 f"a device added with its whole traffic through the VPN gets an IPv6 address in the tunnel, and "
                 f"::/0 in its AllowedIPs: no IPv6 around the tunnel (ROADMAP FND-1d, H1): Address {address!r}, "
                 f"AllowedIPs {allowed!r}"):
        return
    screen = get(opener, "/vpn")
    check('id="vpn-ipv6"' in screen and 'data-reissue="laptop"' in screen and 'data-reissue="phone"' not in screen,
          "...the VPN screen shows the tunnel's IPv6, and marks the device added with its own key, whose "
          "configuration has no IPv6, for reissuing")
    applied = urllib.parse.unquote_plus(post(opener, "/apply", {}))
    wait_for_webui(opener, boot_timeout)
    check(confirm_pending(opener) and "IPv6" in applied and "in the tunnel" in applied,
          "...the Apply brings the tunnel up with IPv6 too, confirmed from the dashboard"
          + ("" if "in the tunnel" in applied else f": {applied[:300]}"))
    if not check(shutil.which("wg") is not None, "...the runner has wireguard-tools for the device's side"):
        return
    router6 = str(ipaddress.IPv6Interface(f"{v6[0].split('/')[0]}/64").network.network_address + 1)
    inside = ["ip", "netns", "exec", VPN_CLIENT_NS]
    with vpn_client(config_text):
        pinged = subprocess.run([*inside, "ping", "-6", "-n", "-c", "3", "-i", "0.5", "-w", "15", router6],
                                capture_output=True, text=True)
        handshake = subprocess.run([*inside, "wg", "show", VPN_CLIENT_LINK, "latest-handshakes"],
                                   capture_output=True, text=True).stdout.strip()
        check(pinged.returncode == 0,
              f"the device reaches the router over IPv6 in the tunnel, at {router6}"
              + ("" if pinged.returncode == 0 else f": {pinged.stdout[-300:]} handshake {handshake!r}"))
        listener = echo_sources_at_isp(8)
        started = time.monotonic()
        out = subprocess.run([*inside, "ping", "-6", "-n", "-c", "2", "-i", "0.5", "-w", "4", ISP_ADDRESS],
                             capture_output=True, text=True)
        took = time.monotonic() - started
        seen = listener.communicate(timeout=30)[0].split()
        check("Administratively prohibited" in out.stdout + out.stderr and not seen,
              f"...its IPv6 to the internet is refused by the router at once, and never reaches the provider: "
              f"{out.stdout.strip()[-200:]} in {took:.1f} s; at the provider: {seen}")
        # The LAN host's stable address, through the zone rule vpn-to-lan.
        # The host routes the tunnel's /64 back through the router's ULA,
        # as a LAN host does through its default route.
        tunnel = ipaddress.IPv6Interface(v6[0]).network.supernet(new_prefix=64)
        ula_host = next((a for a in lan_host_addresses()
                         if a.ip in ipaddress.IPv6Network("fc00::/7") and a.ip in tunnel.supernet(new_prefix=48)), None)
        if not check(ula_host is not None, f"...the LAN host has a stable (ULA) address to be reached at: "
                                           f"{[str(a) for a in lan_host_addresses()]}"):
            return
        route = ["ip", "-6", "route", "replace", str(tunnel), "via", str(ula_host.network.network_address + 1),
                 "dev", LAN_TAP]
        subprocess.run(route, check=True)
        try:
            reached = subprocess.run([*inside, "ping", "-6", "-n", "-c", "3", "-i", "0.5", "-w", "10",
                                      str(ula_host.ip)], capture_output=True, text=True)
        finally:
            subprocess.run(["ip", "-6", "route", "del", str(tunnel), "dev", LAN_TAP], capture_output=True)
        check(reached.returncode == 0,
              f"...and it reaches the LAN host's stable address {ula_host.ip} over IPv6 in the tunnel"
              + ("" if reached.returncode == 0 else f": {reached.stdout[-300:]}"))


def ping_from_lan(target: str, source: str) -> bool:
    proc = subprocess.run(["ping", "-6", "-n", "-c", "3", "-i", "0.5", "-w", "4", "-I", source, target],
                          capture_output=True, text=True)
    return proc.returncode == 0


def tcp_from_lan(target: str, port: int, source: str) -> str:
    """'open', 'refused' or 'no answer' for a TCP connection from the LAN
    host, sent from `source`."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.settimeout(4)
            s.bind((source, 0))
            s.connect((target, port))
        return "open"
    except ConnectionRefusedError:
        return "refused"
    except OSError:
        return "no answer"


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

#: Takes the LAN port down on boot 6's trial, as a kernel that broke the
#: NIC would (ROADMAP SEC-23): the trial fails for that too.
LINK_DOWN_UNIT = Path("etc") / "systemd" / "system" / "fr-boot-test-link-down.service"
LINK_DOWN_WANTS = Path("etc") / "systemd" / "system" / "multi-user.target.wants" / "fr-boot-test-link-down.service"
LINK_DOWN_UNIT_TEXT = """[Unit]
Description=Boot test: the LAN port down on a kernel trial (ROADMAP SEC-23)
ConditionKernelCommandLine=fr_os.kernel=trial
After=fr-firewall.service
Before=fr-kernel-confirm.service

[Service]
Type=oneshot
ExecStart=ip -4 addr flush dev ens4
ExecStart=ip link set dev ens4 down

[Install]
WantedBy=multi-user.target
"""


def unexpected_on_persistence(disk: Path, iso: Path) -> integrity.PersistenceReport:
    """frfw.integrity.persistence_changes on the stick: what its persistence
    layer adds to the image outside FR_OS's own files and what a router
    writes by itself (ROADMAP SEC-22). FR_OS's units are this checkout's."""
    units = Path(__file__).resolve().parents[1] / "systemd"
    own = {f"{integrity.UNITS_DIR}/{unit.name}" for unit in units.glob("fr-*")}
    own |= set(integrity.INSTALLED_FROM_SOURCE.values())
    with image_root(iso) as lower, persistence_partition(disk) as upper:
        return integrity.persistence_changes(lower, upper, own_files=own, pyc_tag="cpython-311")


def system_file_findings(disk: Path, iso: Path) -> system_files.SystemFilesReport:
    with image_root(iso) as lower, persistence_partition(disk) as upper:
        return system_files.check(lower, upper)


def check_persistence_layer(check, disk: Path, iso: Path, when: str) -> None:
    report = unexpected_on_persistence(disk, iso)
    listed = ", ".join(f"{what} {path}" for what, path in report.changes[:20])
    check(not report.changes,
          f"{when}, the persistence layer changes nothing outside FR_OS's files and the router's own state "
          f"(ROADMAP SEC-22; {report.unchecked_pyc} compiled Debian modules not checked by this Python)"
          + (f": {listed}" if listed else ""))
    accounts = system_file_findings(disk, iso)
    problems = accounts.findings[:10] + [f"can log in: {login}" for login in accounts.logins]
    check(not problems,
          "...its accounts, sshd and PAM files hold only what FR_OS and live-config put there, and nobody "
          "can log in but through the webUI (ROADMAP SEC-29)" + (f": {'; '.join(problems)}" if problems else ""))


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
LOCAL_DNS_NAME = "nas.fr-os.test"
LOCAL_DNS_ADDRESS = "10.73.1.20"
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


def dns_answer(server: str, name: str, qtype: int = 1, timeout: float = 3,
               source: str | None = None) -> tuple[int, list[bytes]] | None:
    """(rcode, the answers' RDATA) of one query to `server` -- over IPv6
    for an IPv6 one, sent from `source` if given -- or None without an
    answer."""
    packet = struct.pack("!HHHHHH", 0x4652, 0x0100, 1, 0, 0, 0)
    packet += b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    packet += struct.pack("!HH", qtype, 1)
    with socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            if source:
                sock.bind((source, 0))
            sock.sendto(packet, (server, 53))
            data = sock.recv(4096)
        except OSError:
            return None
    answers, offset = [], len(packet)  # past the echoed question
    for _ in range(struct.unpack("!H", data[6:8])[0]):
        offset += 2 if data[offset] & 0xC0 == 0xC0 else data.index(b"\0", offset) + 1 - offset
        rdlength = struct.unpack("!H", data[offset + 8:offset + 10])[0]
        answers.append(data[offset + 10:offset + 10 + rdlength])
        offset += 10 + rdlength
    return data[3] & 0x0F, answers


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


def upper_issue(upper: Path) -> str:
    """/etc/issue as changed on the persistence partition. Absent when
    nothing rewrote it since first boot stopped doing so (NET-14): the
    image's own file, which holds neither a password nor a port line."""
    path = upper / "etc" / "issue"
    return path.read_text() if path.exists() else ""


def journal(upper: Path, *args: str) -> str:
    return subprocess.run(
        ["journalctl", f"--directory={upper}/var/log/journal", "--no-pager", "-o", "cat", *args],
        capture_output=True, text=True,
    ).stdout


def print_journal(upper: Path, unit: str, *boot: str, lines: int = 25) -> None:
    """The unit's last journal lines, timestamped, into the CI log: the
    QEMU artifacts are not always at hand when a check fails."""
    print(f"    --- journal of {unit} ---")
    for line in journal(upper, *boot, "-u", unit, "-o", "short-monotonic").splitlines()[-lines:]:
        print(f"    {line}")


#: FR_OS services that must be running after a boot, each in its systemd
#: sandbox (security-lessons I1).
#: (fr-apply-helper is socket-activated: it starts on first use.)
LONG_RUNNING = ("fr-webui", "fr-ai-ids", "fr-appid", "fr-tls-fp", "fr-xdp-sni-logger", "fr-console-ports")


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


#: Set when the router got nothing from the provider: boot 3's journal
#: of fr-dhcp6 is printed then.
IPV6_FAILED = False


def check_wan_ipv6(check, opener, provider: Isp) -> str | None:
    """ROADMAP FND-1a, after the Apply that turned IPv6 on: the router
    took an address and a prefix from the provider, answers a ping on its
    WAN address and nothing else, and ignores a forged RA. Returns the
    router's SLAAC address on the WAN."""
    deadline = time.monotonic() + 120
    state, addresses, prefixes = ipv6_card(opener)
    while state != "prefix" and time.monotonic() < deadline:
        time.sleep(5)
        state, addresses, prefixes = ipv6_card(opener)
    found = [re.match(r"([0-9a-f:]+)/(\d+) \((\w+)\)", a) for a in addresses]
    found = [(ipaddress.IPv6Address(m.group(1)), int(m.group(2)), m.group(3)) for m in found if m]
    isp_net = ipaddress.IPv6Network(ISP_PREFIX)
    slaac = [a for a, length, source in found if source == "SLAAC" and a in isp_net and length == 64]
    dhcp = [a for a, length, source in found if source == "DHCPv6" and a in isp_net and length == 128]
    delegated = [p for p in prefixes
                 if ipaddress.IPv6Network(p).subnet_of(ipaddress.IPv6Network(PD_POOL))
                 and ipaddress.IPv6Network(p).prefixlen == 56]
    ok = check(state == "prefix" and bool(delegated),
               f"the router got a /56 from the provider's prefix delegation (ROADMAP FND-1a): {state}, {prefixes}")
    check(bool(slaac) and bool(dhcp),
          f"...and WAN addresses by SLAAC and DHCPv6, in {ISP_PREFIX}: {addresses}")
    check(bool(slaac) and not any(str(a).endswith(WAN_MAC_IID) for a in slaac),
          "...its SLAAC address doesn't carry the WAN port's MAC (RFC 7217)")
    leases = provider.leases()
    check("DHCP6_LEASE_ALLOC" in leases and "DHCP6_PD_LEASE_ALLOC" in leases,
          "...as the provider's DHCPv6 server handed them out")
    if not ok:
        provider.print_logs()
        global IPV6_FAILED
        IPV6_FAILED = True
    if slaac:
        address = str(slaac[0])
        check(ping_sources(address) == {address}, f"the router answers a ping on its WAN address {address}")
        reached = {port: tcp_from_isp(address, port) for port in (WEBUI_PORT, 22)}
        check(set(reached.values()) == {"no answer"},
              f"the webUI and SSH get no answer over IPv6 from the WAN (dropped, ROADMAP FND-1a): {reached}")
    forge_router_advert(FORGED_PREFIX, hop_limit=64)
    time.sleep(10)
    _, addresses, _ = ipv6_card(opener)
    forged = ipaddress.IPv6Network(FORGED_PREFIX)
    taken = [a for a in addresses if ipaddress.IPv6Address(a.split("/")[0]) in forged]
    check(not taken, f"a Router Advertisement that crossed a router (hop limit 64) gives the router nothing: {taken}")
    return str(slaac[0]) if slaac else None


def check_lan_ipv6(check, opener, provider: Isp, wan_address: str | None) -> str | None:
    """ROADMAP FND-1b, after the same Apply: the LAN port got the first
    /64 of the delegated prefix, the host on it took an address there by
    SLAAC from the router's RAs, and reaches the provider through the
    router -- but only from that address (BCP 38), and the provider can't
    reach it. The router itself answers the LAN's ping, nothing else.
    Returns the host's address."""
    global IPV6_FAILED
    if wan_address:
        # The provider routes the delegated prefixes to the router's WAN
        # address, as a provider does.
        isp_run("ip", "-6", "route", "replace", PD_POOL, "via", wan_address, "dev", ISP_DEVICE)
    deadline = time.monotonic() + 90
    lan, network, host = {}, None, None
    while time.monotonic() < deadline:
        solicit_router()
        time.sleep(5)
        _, lan = ipv6_card_lan(opener)
        network = next((ipaddress.IPv6Network(n) for d, n in lan.items() if d.startswith("lan (") and "/" in n),
                       None)
        host = next((a for a in lan_host_addresses() if network and a.ip in network), None)
        if host:
            break
    pool = ipaddress.IPv6Network(PD_POOL)
    check(network is not None and network.subnet_of(pool) and network.prefixlen == 64
          and int(network.network_address) % 2 ** 72 == 0,
          f"the LAN port got the first /64 of the delegated prefix (ROADMAP FND-1b): {lan}")
    ok = check(host is not None, f"the host on the LAN took an address in it by SLAAC from the router's RAs: "
                                 f"{[str(a) for a in lan_host_addresses()]}")
    if not ok:
        IPV6_FAILED = True
        provider.print_logs()
        return None
    source, router = str(host.ip), str(network.network_address + 1)
    subprocess.run(["ip", "-6", "route", "replace", ISP_PREFIX, "via", router, "dev", LAN_TAP], check=True)
    subprocess.run(["ip", "-6", "addr", "add", f"{SPOOFED_SOURCE}/128", "dev", LAN_TAP, "nodad"], check=True)
    listener = echo_sources_at_isp(12)
    time.sleep(1)
    reached = ping_from_lan(ISP_ADDRESS, source)
    ping_from_lan(ISP_ADDRESS, SPOOFED_SOURCE)
    seen = set(listener.communicate(timeout=30)[0].split())
    subprocess.run(["ip", "-6", "addr", "del", f"{SPOOFED_SOURCE}/128", "dev", LAN_TAP], capture_output=True)
    check(reached and source in seen, f"the LAN host reaches the provider over IPv6 through the router: {seen}")
    check(SPOOFED_SOURCE not in seen, "...but only from its own network: a spoofed source is dropped (BCP 38)")
    out = tcp_from_lan(ISP_ADDRESS, 9, source)
    check(out == "refused", f"...TCP too, as the lan-to-wan rule allows (the provider's RST came back): {out}")
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as server:
        server.bind((source, LAN_HOST_PORT))
        server.listen()
        inbound = tcp_from_isp(source, LAN_HOST_PORT)
    check(inbound == "no answer" and not ping_sources(source),
          f"the provider can't reach the LAN host over IPv6, not even a ping (nothing new comes in): {inbound}")
    check(ping_from_lan(router, source), f"the router answers the LAN's ping on its LAN address {router}")
    # ROADMAP FND-1c: the router's stable address on the LAN, a ULA /64
    # advertised next to the delegated one -- the host takes one there too.
    deadline = time.monotonic() + 60
    stable, pinholes = ipv6_card_stable(opener)
    router_ula = next((ipaddress.IPv6Interface(a) for d, a in stable.items() if d.startswith("lan (")), None)
    host_ula = None
    while router_ula and time.monotonic() < deadline:
        host_ula = next((a for a in lan_host_addresses() if a.ip in router_ula.network), None)
        if host_ula:
            break
        solicit_router()
        time.sleep(3)
    check(router_ula is not None and router_ula.ip in ipaddress.IPv6Network("fd00::/8")
          and router_ula.network.prefixlen == 64 and router_ula.ip == router_ula.network.network_address + 1
          and router_ula.ip not in ipaddress.IPv6Network("fd00::/48"),
          f"the router has a stable address on the LAN: <random ULA /48>:<sla>::1/64 (RFC 4193, ROADMAP FND-1c): "
          f"{stable}")
    ok = check(host_ula is not None, f"...advertised: the LAN host took an address in it by SLAAC as well: "
                                     f"{[str(a) for a in lan_host_addresses()]}")
    advert = router_advert()
    check(advert is not None and router_ula is not None and network in advert[0]
          and router_ula.network in advert[0] and not advert[1],
          "the router's RA carries both prefixes, and no DNS server (RDNSS) while its resolver doesn't serve "
          f"the LAN: {advert}")
    if not ok:
        IPV6_FAILED = True
        return source
    ula, ula_source = str(router_ula.ip), str(host_ula.ip)
    check(ping_from_lan(ula, ula_source), f"the router answers on its stable address {ula}")
    listener = echo_sources_at_isp(8)
    time.sleep(1)
    leaked = ping_from_lan(ISP_ADDRESS, ula_source)
    seen = set(listener.communicate(timeout=30)[0].split())
    check(not leaked and ula_source not in seen,
          f"...which never reaches the internet: a ULA source towards the provider is refused (RFC 4193): {seen}")
    services = {(address, port): tcp_from_lan(address, port, own)
                for address, own in ((router, source), (ula, ula_source)) for port in (WEBUI_PORT, 22)}
    check(set(services.values()) == {"no answer"},
          f"the webUI and SSH get no answer over IPv6 while management over IPv6 is off (its default, ROADMAP "
          f"FND-1c): {services}")
    # The admin's pinhole (PINHOLE_YAML): the host's address with that
    # interface ID, whatever the delegated /64 is, and that one port.
    target = str(network.network_address + int(ipaddress.IPv6Address(PINHOLE_IID)))
    check(target in pinholes.get("boot-test-nas", ""),
          f"the card lists the pinhole with the address it leads to now: {pinholes}")
    subprocess.run(["ip", "-6", "addr", "add", f"{target}/64", "dev", LAN_TAP, "nodad"], check=True)
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as opened, \
                socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as other:
            opened.bind((target, PINHOLE_PORT))
            other.bind((target, LAN_HOST_PORT))
            opened.listen()
            other.listen()
            through = tcp_from_isp(target, PINHOLE_PORT)
            beside = tcp_from_isp(target, LAN_HOST_PORT)
    finally:
        subprocess.run(["ip", "-6", "addr", "del", f"{target}/64", "dev", LAN_TAP], capture_output=True)
    check(through == "open", f"the provider reaches the LAN host through its pinhole, TCP {PINHOLE_PORT} "
                             f"(ROADMAP FND-1c): {through}")
    check(beside == "no answer", f"...and no other port of that host: {beside}")
    return source


def check_ipv6_services(check, opener, boot_timeout: float) -> bool:
    """ROADMAP FND-1c, on an Apply of its own: the router's resolver serves
    the LAN (with force-DNS) and management over IPv6 is turned on. The RA
    then names the router's stable address as the LAN's DNS server, it
    answers there, a query to any other server is answered by it too,
    and the webUI and SSH answer on that address only -- not on the
    delegated one. Turned off again on a second Apply: closed. Whether
    both Applies were confirmed."""
    stable, _ = ipv6_card_stable(opener)
    router_ula = next((ipaddress.IPv6Interface(a) for d, a in stable.items() if d.startswith("lan (")), None)
    _, lan = ipv6_card_lan(opener)
    network = next((ipaddress.IPv6Network(n) for d, n in lan.items() if d.startswith("lan (") and "/" in n), None)
    hosts = lan_host_addresses()
    host_ula = next((a for a in hosts if router_ula and a.ip in router_ula.network), None)
    host = next((a for a in hosts if network and a.ip in network), None)
    # ROADMAP DNS-1: a local name, answered by the router's resolver
    # (which serves the LAN for it). The list URL is never fetched.
    post(opener, "/adblock/settings", {"enabled": "true", "source_urls": "https://lists.fr-os.test/hosts",
                                       "serve_lan": "true", "force_dns": "true"})
    post(opener, "/adblock/local-dns/add", {"kind": "hosts", "name": LOCAL_DNS_NAME,
                                            "address": LOCAL_DNS_ADDRESS})
    saved = urllib.parse.unquote_plus(post(opener, "/system/management-ipv6", {"ipv6": "true"}))
    check("Management over IPv6 on" in saved, f"the System screen turns management over IPv6 on: {saved[:300]}")
    applied = urllib.parse.unquote_plus(post(opener, "/apply", {}))
    if not (router_ula and host_ula and host):
        check(False, f"the LAN host has no stable and delegated IPv6 address to go on with: {hosts}")
        wait_for_webui(opener, boot_timeout)
        return confirm_pending(opener)
    ula, ula_source, router, source = str(router_ula.ip), str(host_ula.ip), str(network.network_address + 1), \
        str(host.ip)
    check(ula in applied and "webUI restarting" in applied,
          "the Apply restarts the webUI onto the router's stable address too: the admin's own change "
          "(ROADMAP SEC-27)" + ("" if ula in applied else f": {applied[:300]}"))
    # Only the restarted webUI listens there.
    deadline = time.monotonic() + boot_timeout
    while tcp_from_lan(ula, WEBUI_PORT, ula_source) != "open" and time.monotonic() < deadline:
        time.sleep(1)
    wait_for_webui(opener, boot_timeout)
    confirmed = check(confirm_pending(opener), "...held until confirmed, and confirmed from the dashboard")
    management = {port: tcp_from_lan(ula, port, ula_source) for port in (WEBUI_PORT, 22)}
    # sshd itself is off while nobody has a key (see boot 3's end): the
    # firewall letting SSH through shows as the kernel's refusal.
    check(management == {WEBUI_PORT: "open", 22: "refused"},
          f"with management over IPv6, the webUI answers on the router's stable address {ula}, and SSH is let "
          f"through to it: {management}")
    elsewhere = {port: tcp_from_lan(router, port, source) for port in (WEBUI_PORT, 22)}
    check(set(elsewhere.values()) == {"no answer"},
          f"...and not on its delegated address {router}, which the provider may change: {elsewhere}")
    check_ipv6_jail(check, ula, router_ula.network, ula_source)
    check_ipv6_rules_and_ztna(check, ula, ula_source, source)
    for _ in range(5):  # the resolver was (re)started by the apply
        answer = dns_answer(ula, LOCAL_DNS_NAME, source=ula_source)
        if answer:
            break
        time.sleep(2)
    expected = (0, [socket.inet_aton(LOCAL_DNS_ADDRESS)])
    check(answer == expected, f"the router's resolver answers over IPv6, on its stable address: {answer}")
    for _ in range(3):  # fr-ra was restarted by the apply
        advert = router_advert()
        if advert and advert[1] == [ula]:
            break
    check(advert is not None and advert[1] == [ula],
          f"...which the RA now names as the LAN's DNS server (RDNSS, RFC 8106): {advert}")
    forced = dns_answer(ISP_ADDRESS, LOCAL_DNS_NAME, source=source)
    check(forced == expected,
          f"force-DNS: a query to another server over IPv6 is answered by the router's resolver: {forced}")
    saved = urllib.parse.unquote_plus(post(opener, "/system/management-ipv6", {}))
    applied = urllib.parse.unquote_plus(post(opener, "/apply", {}))
    # The new ruleset closes the ULA at once, while the old webUI process
    # still answers on the LAN's address: wait for it to go away (its
    # restart, a few seconds after the apply), then for the new one.
    wait_until_unreachable(WEBUI_HOST, 120)
    wait_for_webui(opener, boot_timeout)
    confirmed = check(confirm_pending(opener), "management over IPv6 turned off again, on an Apply confirmed "
                                               "from the dashboard" + ("" if "Management over IPv6 off" in saved
                                                                       else f": {saved[:300]}")) and confirmed
    closed = {port: tcp_from_lan(ula, port, ula_source) for port in (WEBUI_PORT, 22)}
    check(set(closed.values()) == {"no answer"}, f"...and the webUI and SSH are closed over IPv6 again: {closed}")
    return confirmed


#: Listens on the provider's side for one TLS connection to port 443 and
#: prints how many bytes of it arrived within 3 s (ROADMAP FND-1d): a
#: ClientHello the SNI filter dropped never does.
_ISP_TLS_LISTENER = """\
import socket, sys, time
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::", 443)); s.listen(1); s.settimeout(20)
print("ready", flush=True)
c, _ = s.accept()
data, deadline = b"", time.time() + 3
try:
    while (left := deadline - time.time()) > 0:
        c.settimeout(left)
        chunk = c.recv(4096)
        if not chunk:
            break
        data += chunk
except OSError:
    pass
print(len(data), data[:1].hex() or "-", flush=True)
"""


def client_hello(server_name: str) -> bytes:
    """Python's own ClientHello naming `server_name`: one segment."""
    context = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_hostname=server_name)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def hello_bytes_at_isp(source: str, record: bytes, cut: int | None = None) -> int:
    """Send `record` from the LAN host's `source` to the provider's port
    443, through the router -- in two segments if `cut` -- and return how
    many of its bytes the provider got (-1 if no connection)."""
    listener = subprocess.Popen(["ip", "netns", "exec", ISP_NS, "python3", "-I", "-c", _ISP_TLS_LISTENER],
                                stdout=subprocess.PIPE, text=True)
    try:
        if listener.stdout.readline().strip() != "ready":
            return -1
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as conn:
            conn.settimeout(5)
            conn.bind((source, 0))
            conn.connect((ISP_ADDRESS, 443))
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            for part in ((record,) if cut is None else (record[:cut], record[cut:])):
                conn.sendall(part)
                time.sleep(0.2)
            time.sleep(3.5)
        got = listener.communicate(timeout=30)[0].split()
        return int(got[0]) if got else -1
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return -1
    finally:
        if listener.poll() is None:
            listener.kill()
            listener.wait()


#: Run in the provider's namespace: answer one datagram on the port in
#: argv[1], and say "ready" once bound.
_ISP_UDP_ECHO = """\
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("::", int(sys.argv[1])))
s.settimeout(10)
print("ready", flush=True)
try:
    data, peer = s.recvfrom(2048)
    s.sendto(b"ok", peer)
except OSError:
    pass
"""


def udp6_to_isp(port: int, source: str, timeout: float = 3) -> str:
    """udp_through_router() over IPv6, from the LAN host's `source` to the
    provider's address. The provider is this runner's own namespace, which
    would refuse a port nobody listens on just like the router's `reject`:
    so it listens, and answers what reaches it -- "answered" is the
    datagram through the router, "refused" the router's reject."""
    listener = subprocess.Popen(["ip", "netns", "exec", ISP_NS, "python3", "-I", "-c", _ISP_UDP_ECHO, str(port)],
                                stdout=subprocess.PIPE, text=True)
    try:
        if listener.stdout.readline().strip() != "ready":
            return "no listener"
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.bind((source, 0))
            sock.connect((ISP_ADDRESS, port))
            try:
                sock.send(b"\xc0" + os.urandom(1199))
                sock.recv(2)
                return "answered"
            except ConnectionRefusedError:
                return "refused"
            except OSError:
                return "no answer"
    finally:
        listener.kill()
        listener.wait()


def check_lan_ipv6_kept(check, opener, host: str | None) -> None:
    """ROADMAP FND-1d, after the Apply that turned the XDP SNI filter on
    on the LAN port. Until 1d the filter read IPv4 only, and the LAN zone
    was taken off IPv6 (FND-1b). It reads IPv6 now: the LAN keeps its
    IPv6, its stable address and its pinhole, and a blocked name's
    ClientHello is dropped over IPv6 too -- whole, or split across
    segments -- while an allowed one goes through; QUIC over IPv6 is
    refused from the port as over IPv4 (ROADMAP SEC-1)."""
    deadline = time.monotonic() + 120  # dhcpcd asks the provider again with its new config
    summary, lan = ipv6_card_lan(opener)
    while not any(d.startswith("lan (") for d in lan) and time.monotonic() < deadline:
        time.sleep(5)
        summary, lan = ipv6_card_lan(opener)
    check(any(d.startswith("lan (") for d in lan) and "Zone lan gets no IPv6" not in summary,
          f"with the SNI filter on the LAN port, the LAN zone keeps its IPv6: the filter reads IPv6 (ROADMAP "
          f"FND-1d): {summary} {lan}")
    stable, pinholes = ipv6_card_stable(opener)
    check(any(d.startswith("lan (") for d in stable),
          f"...and its stable (ULA) address (ROADMAP FND-1c): {stable}")
    check("off" not in pinholes.get("boot-test-nas", "off"),
          f"...and its pinhole stays on: {pinholes}")
    if not host:
        return
    check(ping_from_lan(ISP_ADDRESS, host), "...the router still routes the LAN's IPv6 to the provider")
    allowed = client_hello(XDP_ALLOWED_NAME)
    got = hello_bytes_at_isp(host, allowed)
    check(got == len(allowed), f"a ClientHello naming an allowed host reaches the provider over IPv6, through "
                               f"the XDP filter: {got} of {len(allowed)} bytes")
    got = hello_bytes_at_isp(host, client_hello(XDP_BLOCKED_NAME))
    check(got == 0, f"...one naming a blocked host is dropped over IPv6 (ROADMAP FND-1d): {got} bytes arrived")
    record, cut = split_client_hello(XDP_BLOCKED_NAME)
    got = hello_bytes_at_isp(host, record, cut)
    check(0 <= got < len(record), f"...so is a browser-sized one, split across segments, whose name is in the "
                                  f"second (ROADMAP SEC-17): {got} of {len(record)} bytes arrived")
    quic, other = udp6_to_isp(443, host), udp6_to_isp(4443, host)
    check(quic == "refused" and other == "answered",
          f"...and QUIC over IPv6 is refused from the filtered port (ROADMAP SEC-1): UDP/443 {quic}, "
          f"UDP/4443 {other}")


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

    print("boot 6: a new trial, with the webUI masked and the LAN port down -- the router doesn't come up")
    stage_kernel(disk, iso, version)
    with persistence_partition(disk, writable=True) as upper:
        unit = upper / WEBUI_UNIT
        unit.parent.mkdir(parents=True, exist_ok=True)
        saved = unit.read_bytes() if unit.exists() and not unit.is_symlink() else None
        unit.unlink(missing_ok=True)
        unit.symlink_to("/dev/null")
        # ROADMAP SEC-23: as if the kernel broke the LAN NIC -- on the
        # trial boot only. Its address goes too: since FND-1d the LAN
        # keeps IPv6 with the SNI filter on, and dhcpcd, which hands the
        # LAN its delegated prefix, sets a port it serves back up.
        (upper / LINK_DOWN_UNIT).write_text(LINK_DOWN_UNIT_TEXT)
        (upper / LINK_DOWN_WANTS).parent.mkdir(parents=True, exist_ok=True)
        (upper / LINK_DOWN_WANTS).symlink_to(f"/{LINK_DOWN_UNIT}")
    vm = Vm(workdir, disk, 6, kvm, uefi)
    rebooted = vm.wait_exit(boot_timeout + kernel_boot.HEALTH_TIMEOUT + 60)
    vm.kill()
    log = vm.log()
    check("fr_os.kernel=trial" in command_line(log), "GRUB booted the staged kernel for its trial")
    check(rebooted, "the router rebooted by itself when its check failed")
    with persistence_partition(disk, writable=True) as upper:
        confirm = journal(upper, "-b", "-u", "fr-kernel-confirm.service")
        check("failed its trial boot" in confirm and "the webUI does not answer" in confirm,
              "...because the webUI did not answer")
        check(f"ens4 is not up with its address {WEBUI_HOST}/24" in confirm,
              "...and because the LAN port is down, which the applied config needs up (ROADMAP SEC-23)")
        if "failed its trial" not in confirm or "ens4 is not up" not in confirm:
            print_journal(upper, "fr-kernel-confirm.service", "-b")
        check(kernel_env(upper).get("fr_os_state") == "trying", "...leaving the trial unconfirmed ('trying')")
        unit = upper / WEBUI_UNIT
        unit.unlink()
        if saved is not None:
            unit.write_bytes(saved)
        (upper / LINK_DOWN_WANTS).unlink()
        (upper / LINK_DOWN_UNIT).unlink()

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
        # ROADMAP SEC-23: "Try it" recorded what worked, and the trial was
        # checked against it -- the links, the XDP filter, the VPN, Kea.
        confirm = journal(upper, "-b", "-u", "fr-kernel-confirm.service")
        recorded = re.search(r"what worked before it works: (.*)", confirm)
        check(recorded is not None and all(item in recorded.group(1) for item in (
                  "links ens3, ens4", f"ens4 {WEBUI_HOST}/24", "XDP on ens4", "wg0", "kea-dhcp4-server.service")),
              "the trial was checked against what worked when it was started: links, addresses, XDP, the VPN, "
              "the services (ROADMAP SEC-23)" + (f": {recorded.group(1)[:300]}" if recorded else ""))
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
    workdir = (args.workdir or Path(tempfile.mkdtemp(prefix="fros-qemu-"))).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    args.workdir = workdir
    with lan_tap(), isp(workdir) as provider:
        return run(args, provider)


def run(args: argparse.Namespace, provider: Isp) -> int:
    workdir = args.workdir
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
    check(page is not None and "Sign in" in page, f"webUI answers on https://{WEBUI_HOST}/ from the LAN")
    check(vm.power_off(), "the power button shuts it down cleanly")
    vm.kill()
    with persistence_partition(disk) as upper:
        first_boot = journal(upper, "-u", "fr-first-boot.service")
        check("fr-first-boot: done" in first_boot, "fr-first-boot finished"
              + ("" if "did not start" not in first_boot else " (some units did not start)"))
        # ROADMAP SEC-8: the WAN is the port where a DHCP server answered
        # (QEMU's user network), not the first one by chance.
        chosen = re.search(r"fr-first-boot: WAN/LAN: (.*)", first_boot)
        check(chosen is not None and chosen.group(1).startswith("a DHCP server answered on ens3 only")
              and "assigned WAN=ens3 LAN=ens4" in first_boot,
              "first boot chose the WAN by where a DHCP server answered (ROADMAP SEC-8)"
              + (f": {chosen.group(1)}" if chosen else ""))
        # ROADMAP NET-12: the upstream is a home router's 192.168.1.0/24;
        # the LAN is outside it.
        check(chosen is not None and f"(offering {UPSTREAM_NET})" in chosen.group(1)
              and f"LAN {WEBUI_HOST}/24 with DHCP" in first_boot,
              f"first boot saw the upstream's {UPSTREAM_NET} and put the LAN at {WEBUI_HOST}, out of its way "
              "(ROADMAP NET-12)")
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
        check(bool(password) and password not in upper_issue(upper),
              "...and not in the world-readable /etc/issue")
        # NET-13 follow-up: every port, its link and role, and the webUI's
        # address on the console, from fr-console-ports -- not a line
        # first boot wrote once into /etc/issue.
        ports = upper / "etc" / "issue.d" / "fr_os-ports.issue"
        ports_text = ports.read_text() if ports.exists() else ""
        port_lines = {line.split()[0]: line for line in ports_text.splitlines()[1:] if line.startswith("  ")}
        check("WAN" in port_lines.get("ens3", "") and "LAN" in port_lines.get("ens4", "")
              and "link" in port_lines.get("ens4", "") and "webUI: https://" in ports_text,
              "the console lists every port with its link and role, and the webUI's address (fr_os-ports.issue)")
        check("FR_OS webUI:" not in upper_issue(upper),
              "...and first boot no longer writes a one-off line into /etc/issue")
        check((upper / "etc" / "fr_os" / "config.yaml").exists(), "config.yaml is on the persistence partition")
    # ROADMAP FND-1c: the admin's pinhole, written into config.yaml by hand
    # (PINHOLE_YAML); first boot's config has no ipv6 section.
    with persistence_partition(disk, writable=True) as upper:
        config_file = upper / "etc" / "fr_os" / "config.yaml"
        text = config_file.read_text() if config_file.exists() else ""
        check(bool(text) and not re.search(r"^ipv6:", text, re.M),
              "first boot's config.yaml has no ipv6 section; the boot test's pinhole goes in by hand")
        rules_at = re.search(r"^rules:\n(?=- )", text, re.M)
        check(rules_at is not None, "first boot's config.yaml has rules; the boot test's IPv6 ones go first")
        if text and rules_at:
            text = text[:rules_at.end()] + RULES_V6 + text[rules_at.end():]
            config_file.write_text(text.rstrip("\n") + "\n" + PINHOLE_YAML)
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
        # ROADMAP FND-1a: the provider's RAs have been on the WAN since
        # boot 1; with IPv6 off the router took none of them, answers
        # nothing over IPv6 and asked the provider for nothing.
        silent = ping_sources(f"ff02::1%{ISP_DEVICE}")
        check(not silent and not provider.leases(),
              "with IPv6 off, the router answers nothing over IPv6 on the WAN and asks the provider for nothing "
              f"(ROADMAP FND-1a){': ' + ', '.join(sorted(silent)) if silent else ''}")
        post(opener, "/interfaces/ipv6", {"enabled": "true"})
        # ROADMAP FND-1b: IPv6 on an Apply of its own, before the XDP SNI
        # filter below takes the LAN zone off it.
        first = urllib.parse.unquote_plus(post(opener, "/apply", {}))
        check("confirm it within 300 s" in first and confirm_pending(opener),
              "the Apply turning IPv6 on is held, and confirmed from the dashboard"
              + ("" if "confirm it" in first else f": {first[:300]}"))
        wan_address = check_wan_ipv6(check, opener, provider)
        lan_host = check_lan_ipv6(check, opener, provider, wan_address)
        # ROADMAP SEC-6: the ZTNA gate, with one user, signed in over IPv6
        # (check_ipv6_rules_and_ztna) and over IPv4 below; ROADMAP FND-1d:
        # it gates one of the rules by IPv6 address (RULES_V6_YAML).
        post(opener, "/ztna/users/add", {"new_username": ZTNA_USERNAME, "new_password": ZTNA_PASSWORD})
        post(opener, "/ztna/settings", {"enabled": "true", "session_ttl_seconds": "3600"})
        rules_page = get(opener, "/rules")
        check(all(name in rules_page for name in ("boot-test-drop-v6", "boot-test-ztna-v6")),
              "the Rules screen lists the rules by IPv6 address written before boot 3 (ROADMAP FND-1d)")
        if lan_host:
            check_ipv6_services(check, opener, boot_timeout)
        else:  # the resolver's settings, for ROADMAP DNS-1 below
            post(opener, "/adblock/settings", {"enabled": "true", "source_urls": "https://lists.fr-os.test/hosts",
                                               "serve_lan": "true", "force_dns": "true"})
            post(opener, "/adblock/local-dns/add", {"kind": "hosts", "name": LOCAL_DNS_NAME,
                                                    "address": LOCAL_DNS_ADDRESS})
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
        # ROADMAP DNS-1: the local name set before (check_ipv6_services).
        for _ in range(5):  # the resolver may have been restarted by the apply
            local_answer = dns_answer(WEBUI_HOST, LOCAL_DNS_NAME)
            if local_answer:
                break
            time.sleep(2)
        check(local_answer == (0, [socket.inet_aton(LOCAL_DNS_ADDRESS)])
              and dns_answer(WEBUI_HOST, LOCAL_DNS_NAME, qtype=28) == (0, []),
              f"the router's resolver answers the local name {LOCAL_DNS_NAME} itself (ROADMAP DNS-1)"
              + ("" if local_answer else f": no answer; {applied[:300]}"))
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
        check_lan_ipv6_kept(check, opener, lan_host)
        check_vpn_ipv6(check, opener, boot_timeout)
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
        # ROADMAP FND-1d: the AI IDS, which starts at boot -- in boot 4,
        # where a LAN host scans over IPv6 (check_ids_ipv6).
        ids_saved = urllib.parse.unquote_plus(post(opener, "/ai-ids/settings", {
            "enabled": "true", "quarantine_duration_seconds": "7200"}))
        check("AI IDS settings saved" in ids_saved, f"the AI IDS screen turns it on: {ids_saved[:300]}")
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
              and password not in upper_issue(upper),
              "once changed in the webUI, the initial password is gone from the console")
        config = (upper / "etc" / "fr_os" / "config.yaml").read_text()
        check("Europe/Budapest" in config, "a change made in the webUI was saved to the persistence partition")
        check_sandboxed_services(check, upper, "-b")
        dhcp6 = journal(upper, "-b", "-u", "fr-dhcp6.service")
        check("Started" in dhcp6, "dhcpcd (fr-dhcp6) ran in its sandbox once IPv6 was turned on (ROADMAP FND-1a)")
        if "Started" not in dhcp6 or "Failed" in dhcp6 or IPV6_FAILED:
            print("    --- journal of fr-dhcp6.service (from its start) ---")
            text = journal(upper, "-b", "-u", "fr-dhcp6.service", "-o", "short-monotonic")
            for line in [l for l in text.splitlines() if "No such process" not in l][:80]:
                print(f"    {line}")
        ra = journal(upper, "-b", "-u", "fr-ra.service")
        check("Started" in ra and "Failed" not in ra,
              "dnsmasq (fr-ra) sent the LAN's Router Advertisements in its sandbox, as a dynamic account "
              "(ROADMAP FND-1b)")
        if "Started" not in ra or "Failed" in ra or IPV6_FAILED:
            print("    --- journal of fr-ra.service ---")
            for line in journal(upper, "-b", "-u", "fr-ra.service", "-o", "short-monotonic").splitlines()[:60]:
                print(f"    {line}")
        dropped_events = xdp_blocked_events(upper)
        check(any('"action": "drop"' in line for line in dropped_events),
              "the dropped ClientHello is in the XDP SNI event file (ROADMAP P4-1, SEC-4)")
        # ROADMAP SEC-28: the filter checks a followed segment's TCP
        # checksum, so it must see segments as sent -- in generic mode,
        # after GRO, only with the device's GRO off. (The split hello
        # above got its answer through that check.)
        xdp_state = json.loads((upper / "etc" / "fr_os" / "xdp_state.json").read_text())
        xdp_mode = xdp_state.get("attached", {}).get("ens4")
        check((xdp_mode, xdp_state.get("gro_off")) in (("xdpdrv", []), ("xdpgeneric", ["ens4"])),
              f"GRO is off where the XDP filter runs after it (ROADMAP SEC-28): {xdp_mode}, "
              f"GRO turned off on {xdp_state.get('gro_off')}")
        check("Server listening" not in journal(upper, "-b", "-u", "ssh.service"),
              "sshd did not listen at all this boot (off while nobody has a key)")
        # ROADMAP SEC-18: Debian's nftables.service would load
        # /etc/nftables.conf (`flush ruleset`) over the FR_OS ruleset.
        with image_root(args.iso) as root:
            check(nftables_unit_masked(root, upper),
                  "Debian's nftables.service is masked, and persistence didn't unmask it")
            # ROADMAP FND-4: Realtek NICs that need rtl_nic firmware
            # work out of the box.
            check(any((root / "lib" / "firmware" / "rtl_nic").glob("rtl8168*")),
                  "the image carries the Realtek NIC firmware (lib/firmware/rtl_nic)")
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

    # ROADMAP SEC-22: after three boots, an update attempt, a password
    # change and applies, the persistence layer holds only the router's
    # own state; an attacker's unit and SSH key planted on it are found.
    check_persistence_layer(check, disk, Path(args.iso), "after boot 3")
    planted = ("etc/systemd/system/fr-boot-test-implant.service", "root/.ssh/authorized_keys")
    created = []
    with image_root(Path(args.iso)) as lower, persistence_partition(disk, writable=True) as upper:
        for path in planted:
            # Its directories as overlayfs copies them up: the image's mode
            # and owner, so only the planted files differ from the image.
            for parent in reversed(Path(path).parents[:-1]):
                if not (upper / parent).exists():
                    (upper / parent).mkdir(mode=0o700)
                    created.append(parent)
                    if (lower / parent).is_dir():
                        image = (lower / parent).lstat()
                        os.chown(upper / parent, image.st_uid, image.st_gid)
                        os.chmod(upper / parent, stat.S_IMODE(image.st_mode))
            (upper / path).write_text("stands in for an attacker's persistence\n")
    found = unexpected_on_persistence(disk, Path(args.iso)).changes
    check(found == [("added", "/" + path) for path in sorted(planted)],
          f"...and finds a unit and an SSH key planted on it (ROADMAP SEC-22): {found}")
    # ROADMAP SEC-29: the key lets root log in, and a second uid-0
    # account added to /etc/passwd is found.
    with persistence_partition(disk, writable=True) as upper:
        passwd = (upper / "etc/passwd").read_text()
        (upper / "etc/passwd").write_text(passwd + "toor:x:0:0::/root:/bin/sh\n")
    accounts = system_file_findings(disk, Path(args.iso))
    # (toor shares root's home, so the key lets it in too)
    check("/etc/passwd: toor has uid 0" in accounts.findings
          and accounts.logins == ["root: SSH key", "toor: SSH key"],
          f"...and that root can log in with the key, and a second uid-0 account (ROADMAP SEC-29): "
          f"{accounts.findings} {accounts.logins}")
    with persistence_partition(disk, writable=True) as upper:
        (upper / "etc/passwd").write_text(passwd)
        for path in planted:
            (upper / path).unlink()
        for parent in reversed(created):
            (upper / parent).rmdir()
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
    ids_held = check_ids_ipv6(check, opener) if landed else False
    check(vm.power_off(), "powered off")
    vm.kill()
    with persistence_partition(disk) as upper:
        if not ids_held:  # say why, right here in the CI log
            print_journal(upper, "fr-ai-ids.service", "-b", lines=40)
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
        check(bool(listening) and WEBUI_HOST in listening[-1] and SPARE_ADDRESS.split("/")[0] not in listening[-1],
              "the webUI listens on the applied config's addresses, not config.yaml's (ROADMAP SEC-5)"
              + (f": {listening[-1]}" if listening else ""))
        failed = sorted(set(re.findall(r"Failed to start (\S+)", journal(upper, "-b"))))
        check(not failed, f"no unit failed to start{': ' + ', '.join(failed) if failed else ''}")

    run_kernel_trials(check, workdir, disk, Path(args.iso), kvm, uefi, boot_timeout)
    run_kernel_update_from_the_webui(check, workdir, disk, Path(args.iso), kvm, uefi, boot_timeout)
    check_persistence_layer(check, disk, Path(args.iso), "after the kernel trials and update")

    print()
    if check.failures:
        print(f"{len(check.failures)} check(s) failed; logs in {workdir}")
        return 1
    print(f"all checks passed; logs in {workdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
