"""Kernel fixes without a new image: a kernel staged on the persistence
partition, tried once, and kept only when the router comes up on it
(ROADMAP SEC-14, review v0.2.0 R3).

A live-booted FR_OS boots the kernel on its boot medium, so a Debian
kernel security fix used to need a new image. Now a kernel (and an initrd
built for it) can be *staged*: copied to the persistence partition's own
root -- next to the overlay's `rw/`, never inside it -- as

    fr_os-boot/staged/vmlinuz, initrd.img, SHA256SUMS
    fr_os-boot/grubenv          (a GRUB environment block)

GRUB, which both firmwares run (installer/live-build/config/includes.binary/
boot/grub/grub.cfg), reads two variables from grubenv, `fr_os_staged` (the
version) and `fr_os_state`, and runs this state machine:

    trial    staged, never booted   -> GRUB writes "trying", boots it
    good     confirmed              -> GRUB writes "booting", boots it
    trying / booting still there    -> that boot never confirmed: GRUB
             writes "failed" and boots the image's own kernel
    failed / nothing staged         -> the image's own kernel

GRUB writes the new state *before* it boots the staged kernel and boots
it only if the write worked, so a kernel that panics (`panic=10` reboots
it) or hangs (the hardware watchdog reboots it, systemd's
RuntimeWatchdogSec) is tried once, not over and over. It also checks the
files against SHA256SUMS first: a torn copy or a failing stick is a
failure like any other.

Late in every boot GRUB marked (`fr_os.kernel=` on the kernel command
line) `confirm_boot` runs (fr-kernel-confirm.service): on the staged
kernel it checks the router is up -- the firewall's ruleset loaded, the
applied config's network devices there, the webUI answering, persistence
active -- and that what worked before the trial works again (ROADMAP
SEC-23, review v0.2.1 FR-NEW-003): `stage` records it in the slot
(`expect.json`) -- the ports that had a link, the interfaces' addresses,
the XDP filter's attachments, the WireGuard tunnel, the FR_OS services
that ran -- so a kernel that breaks a NIC's link, XDP, WireGuard or Kea
fails its trial, while a port without a cable or a service already
stopped doesn't fail a good one. Then it writes "good". A *trial* that fails the check reboots once
into the image's kernel (the admin rebooted into the trial; a router left
unreachable is worse); a confirmed kernel that fails it later stays up,
says so, and the next boot falls back. A fallback boot raises a security
alert. Nothing here ever reboots the router otherwise: staging a kernel
doesn't, the admin reboots into it.

What the hashes protect against, and what not: corruption, not root.
Whoever is root on the router can rewrite the stick anyway, the image
included -- that is what scripts/verify-medium.py, run on another
computer, is for (it lists the staged kernel too).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from frfw import persistence

BOOT_DIR_NAME = "fr_os-boot"
ENV_NAME = "grubenv"
SLOT = "staged"
KERNEL = "vmlinuz"
INITRD = "initrd.img"
SUMS = "SHA256SUMS"
#: What worked when the kernel was staged, to work again on its boot
#: (ROADMAP SEC-23).
EXPECT = "expect.json"

STATE = "fr_os_state"
STAGED = "fr_os_staged"
TRIAL, TRYING, GOOD, BOOTING, FAILED = "trial", "trying", "good", "booting", "failed"
STATES = (TRIAL, TRYING, GOOD, BOOTING, FAILED)

#: What GRUB puts on the kernel command line (`fr_os.kernel=`): the
#: staged kernel on its first boot or a later one, the image's kernel
#: because the staged one failed, or the image's kernel as usual.
BOOT_TRIAL, BOOT_STAGED, BOOT_FALLBACK, BOOT_IMAGE = "trial", "staged", "fallback", "image"

#: GRUB's environment block: exactly this size, this header, '#' padding
#: (grub-core/lib/envblk.c).
ENV_SIZE = 1024
ENV_HEADER = b"# GRUB Environment Block\n"

#: A Debian kernel release ("6.1.0-28-amd64"); it is shown in GRUB's menu
#: and written to grubenv, so nothing else.
_VERSION = re.compile(r"[0-9][A-Za-z0-9.+~_-]{0,63}\Z")

#: Room left on the persistence partition after staging.
SPARE_BYTES = 64 * 2**20

#: How long a staged kernel's boot has to come up.
HEALTH_TIMEOUT = 180.0
WEBUI_PORT = 443

_CMDLINE_PATH = Path("/proc/cmdline")
_MOUNTS_PATH = Path("/proc/mounts")


class KernelBootError(Exception):
    """A kernel could not be staged or unstaged; nothing was changed
    unless the message says otherwise."""


# -- the environment block -------------------------------------------------------


def format_env(values: dict[str, str]) -> bytes:
    body = ENV_HEADER
    for name, value in values.items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or not re.fullmatch(r"[A-Za-z0-9.+~_-]*", value):
            raise KernelBootError(f"not a value for the boot environment: {name}={value!r}")
        body += f"{name}={value}\n".encode()
    if len(body) > ENV_SIZE:
        raise KernelBootError("the boot environment is full")
    return body + b"#" * (ENV_SIZE - len(body))


def parse_env(data: bytes) -> dict[str, str]:
    """The variables of an environment block; {} for anything else."""
    if len(data) != ENV_SIZE or not data.startswith(ENV_HEADER):
        return {}
    values = {}
    for line in data[len(ENV_HEADER):].decode("utf-8", "replace").split("\n"):
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name] = value
    return values


def read_env(path: Path) -> dict[str, str]:
    try:
        return parse_env(path.read_bytes())
    except OSError:
        return {}


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_synced(path: Path, data: bytes) -> None:
    with path.open("wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _copy_synced(source: Path, target: Path) -> None:
    with source.open("rb") as src, target.open("wb") as dst:
        shutil.copyfileobj(src, dst, 1 << 20)
        dst.flush()
        os.fsync(dst.fileno())


def write_env(path: Path, values: dict[str, str]) -> None:
    """Replace the block in one step (a new file, synced, renamed over the
    old one, the directory synced): a power cut leaves the old block or
    the new one. GRUB finds the file's blocks again at every boot."""
    data = format_env(values)
    tmp = path.with_name(f".{path.name}.new")
    _write_synced(tmp, data)
    tmp.replace(path)
    _fsync_dir(path.parent)


# -- where it lives ----------------------------------------------------------------


def persistence_root(mounts_text: str | None = None) -> Path | None:
    """Where live-boot mounted the persistence filesystem it uses (the
    one holding `rw/`), or None: not live, or no persistence."""
    if mounts_text is None:
        try:
            mounts_text = _MOUNTS_PATH.read_text()
        except OSError:
            return None
    for line in mounts_text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith(persistence.LIVE_PERSISTENCE_PREFIX):
            return Path(parts[1].replace("\\040", " "))
    return None


def boot_dir(mounts_text: str | None = None) -> Path | None:
    root = persistence_root(mounts_text)
    return None if root is None else root / BOOT_DIR_NAME


def boot_mode(cmdline: str | None = None) -> str | None:
    """`fr_os.kernel=` of this boot, or None (not started by FR_OS's GRUB)."""
    if cmdline is None:
        try:
            cmdline = _CMDLINE_PATH.read_text()
        except OSError:
            return None
    for arg in cmdline.split():
        if arg.startswith("fr_os.kernel="):
            return arg.split("=", 1)[1]
    return None


# -- staging -------------------------------------------------------------------------


def check_version(version: str) -> str:
    if not _VERSION.match(version):
        raise KernelBootError(f"not a kernel version: {version!r}")
    return version


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_linux_kernel(path: Path) -> bool:
    """An x86 Linux boot image: the setup header's "HdrS" at 0x202."""
    try:
        with path.open("rb") as fh:
            fh.seek(0x202)
            return fh.read(4) == b"HdrS"
    except OSError:
        return False


def stage(kernel: Path, initrd: Path, version: str, *, boot_dir: Path, expect: dict | None = None) -> None:
    """Make `kernel` + `initrd` the staged kernel, to be tried at the next
    boot. A crash at any point leaves either the previous state or
    nothing staged -- never a half-copied kernel marked for a trial.
    `expect`: what works now (`expectations`), checked again on its boot;
    without it, what the applied config turns on is."""
    check_version(version)
    if not _is_linux_kernel(kernel):
        raise KernelBootError(f"{kernel} is not a Linux kernel image")
    if not initrd.is_file() or initrd.stat().st_size == 0:
        raise KernelBootError(f"{initrd} is not an initrd")
    if not boot_dir.parent.is_dir():
        raise KernelBootError(f"{boot_dir.parent} is not there: no persistence partition in use")
    needed = kernel.stat().st_size + initrd.stat().st_size + SPARE_BYTES
    free = shutil.disk_usage(boot_dir.parent).free
    if free < needed:
        raise KernelBootError(f"only {free // 2**20} MiB free on the persistence partition, "
                              f"{needed // 2**20} MiB needed")
    boot_dir.mkdir(mode=0o700, exist_ok=True)
    env_path = boot_dir / ENV_NAME
    slot = boot_dir / SLOT
    # Nothing staged while the slot changes.
    write_env(env_path, {})
    new = boot_dir / f"{SLOT}.new"
    shutil.rmtree(new, ignore_errors=True)
    new.mkdir(mode=0o700)
    sums = []
    for source, name in ((kernel, KERNEL), (initrd, INITRD)):
        _copy_synced(source, new / name)
        sums.append(f"{_sha256(new / name)}  {name}\n")
    _write_synced(new / SUMS, "".join(sums).encode())
    if expect is not None:
        _write_synced(new / EXPECT, json.dumps(expect, sort_keys=True).encode())
    _fsync_dir(new)
    shutil.rmtree(slot, ignore_errors=True)
    new.replace(slot)
    _fsync_dir(boot_dir)
    write_env(env_path, {STATE: TRIAL, STAGED: version})


def unstage(*, boot_dir: Path) -> bool:
    """Back to the image's kernel at the next boot. False: nothing was staged."""
    env_path = boot_dir / ENV_NAME
    if not env_path.exists() and not (boot_dir / SLOT).exists():
        return False
    write_env(env_path, {})
    shutil.rmtree(boot_dir / SLOT, ignore_errors=True)
    return True


def staged_files(boot_dir: Path) -> dict[str, str]:
    """name -> SHA256 of the staged files, as they are now."""
    slot = boot_dir / SLOT
    return {name: _sha256(slot / name) for name in (KERNEL, INITRD) if (slot / name).is_file()}


def files_intact(boot_dir: Path) -> bool:
    """Whether the staged files match their SHA256SUMS -- GRUB's check."""
    try:
        listed = dict(reversed(line.split(None, 1)) for line in
                      (boot_dir / SLOT / SUMS).read_text().splitlines() if line.strip())
    except (OSError, ValueError):
        return False
    listed = {name.strip(): digest for name, digest in listed.items()}
    return set(listed) == {KERNEL, INITRD} and staged_files(boot_dir) == listed


# -- status -------------------------------------------------------------------------


@dataclass
class KernelStatus:
    available: bool  # a live system with persistence: a kernel can be staged
    state: str | None = None
    staged: str | None = None
    boot: str | None = None  # this boot's fr_os.kernel=
    running: str = field(default_factory=lambda: os.uname().release)
    intact: bool | None = None

    @property
    def summary(self) -> str:
        if not self.available:
            return "no persistence partition in use: a kernel can't be staged"
        running = f"running kernel {self.running}"
        if self.boot == BOOT_FALLBACK:
            running += " -- the image's own: the staged kernel failed, see the security alerts"
        elif self.boot in (BOOT_TRIAL, BOOT_STAGED):
            running += " -- the staged one"
        if not self.state:
            return f"{running}; nothing staged"
        what = {
            TRIAL: "staged, tried at the next reboot",
            TRYING: "on its trial boot",
            GOOD: "confirmed: boots by default, every boot checked",
            BOOTING: "booted, not confirmed yet",
            FAILED: "failed: the image's own kernel boots",
        }.get(self.state, f"in an unknown state ({self.state})")
        broken = "" if self.intact in (None, True) else " -- ITS FILES DON'T MATCH THEIR HASHES"
        return f"{running}; kernel {self.staged or '?'} {what}{broken}"


def status(*, boot_dir_path: Path | None = None, cmdline: str | None = None,
           check_files: bool = True) -> KernelStatus:
    path = boot_dir() if boot_dir_path is None else boot_dir_path
    if path is None:
        return KernelStatus(available=False, boot=boot_mode(cmdline))
    env = read_env(path / ENV_NAME)
    state = env.get(STATE) or None
    return KernelStatus(available=True, state=state, staged=env.get(STAGED) or None, boot=boot_mode(cmdline),
                        intact=files_intact(path) if state and check_files else None)


# -- the boot-time check ----------------------------------------------------------------


def _firewall_loaded() -> bool:
    from frfw.nft.builder import FILTER_TABLE

    proc = subprocess.run(["nft", "list", "table", "inet", FILTER_TABLE], capture_output=True, text=True)
    return proc.returncode == 0


def _webui_answers(port: int = WEBUI_PORT) -> bool:
    """On loopback, which it always listens on (frfw.management.listen_addresses)."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3):
            return True
    except OSError:
        return False


def health_problems(expect: dict | None = None) -> list[str]:
    """What is wrong with this boot, now; [] when the router is up.
    `expect`: what worked before the trial (ROADMAP SEC-23) -- by default
    the staged kernel's record; without one, what the applied config
    turns on."""
    from frfw import provision

    if expect is None:
        where = boot_dir()
        expect = read_expect(where) if where is not None else None
    problems = []
    if not _firewall_loaded():
        problems.append("the firewall's ruleset is not loaded")
    applied = provision.load_applied_config()
    if applied is not None:
        missing = provision.missing_devices(applied)
        if missing:
            problems.append(f"network devices of the applied config are missing: {', '.join(missing)}")
        if expect is None:
            expect = config_expectations(applied)
    if expect is not None:
        problems.extend(expectation_problems(expect))
    if not _webui_answers():
        problems.append("the webUI does not answer")
    if not persistence.status().active:
        problems.append("persistence is not active")
    return problems


# -- what worked before the trial (ROADMAP SEC-23) ---------------------------------------

#: The services a trial must find running again if they ran before it:
#: what FR_OS starts, and the servers it configures.
EXPECTED_SERVICES = (
    "fr-webui.service", "fr-apply-helper.socket", "kea-dhcp4-server.service", "fr-adblock-dns.service",
    "fr-xdp-sni-logger.service", "fr-ai-ids.service", "fr-appid.service", "fr-tls-fp.service", "ssh.service",
)


def network_now(run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> dict[str, dict]:
    """Every network device: whether it is up, has a link (carrier), has
    an XDP program, and its IPv4 addresses -- from `ip -j`, netlink only."""
    def ip_json(*args: str) -> list:
        proc = run(["ip", "-j", *args], capture_output=True, text=True)
        try:
            return json.loads(proc.stdout) if proc.returncode == 0 else []
        except ValueError:
            return []

    devices: dict[str, dict] = {}
    for link in ip_json("link", "show"):
        flags = link.get("flags") or []
        devices[link["ifname"]] = {"up": "UP" in flags, "carrier": "LOWER_UP" in flags, "xdp": "xdp" in link,
                                   "addresses": []}
    for link in ip_json("addr", "show"):
        entry = devices.setdefault(link["ifname"], {"up": False, "carrier": False, "xdp": False, "addresses": []})
        entry["addresses"] = sorted(f"{a['local']}/{a['prefixlen']}" for a in link.get("addr_info") or []
                                    if a.get("family") == "inet")
    return devices


def service_active(unit: str) -> bool:
    try:
        return subprocess.run(["systemctl", "is-active", "--quiet", "--", unit], timeout=30).returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _config_devices(config) -> tuple[set[str], dict[str, str], list[str]]:
    """The devices the config uses, its addresses (device -> address), and
    the devices the XDP filter attaches to (a VLAN's parent carries it)."""
    devices, addresses = set(), {}
    vlans = {i.device for i in config.interfaces.values() if i.vlan_id is not None}
    for iface in config.interfaces.values():
        devices.add(iface.vlan_parent if iface.vlan_id is not None else iface.device)
        if iface.address:
            addresses[iface.device] = str(ipaddress.IPv4Interface(iface.address))
    xdp = []
    if config.xdp_sni_filter.enabled:
        xdp = sorted({config.interfaces[n].device for n in config.xdp_sni_filter.interfaces} - vlans)
    return devices, addresses, xdp


def config_expectations(config) -> dict:
    """Without a record of the moment it was staged: what the applied
    config turns on -- no links (a port may have no cable) and no services."""
    _, addresses, xdp = _config_devices(config)
    return {"carrier": [], "addresses": addresses, "xdp": xdp, "wireguard": bool(config.wireguard.enabled),
            "services": []}


def expectations(config, *, now: dict | None = None,
                 active: Callable[[str], bool] = service_active) -> dict:
    """What works now and must work again on a staged kernel's boot: the
    config's ports that have a link, its addresses that are there, the
    XDP filter's attachments, the WireGuard tunnel if up, the services
    that run (ROADMAP SEC-23)."""
    now = network_now() if now is None else now
    devices, addresses, xdp = _config_devices(config)
    return {
        "carrier": sorted(d for d in devices if now.get(d, {}).get("carrier")),
        "addresses": {d: a for d, a in addresses.items() if a in now.get(d, {}).get("addresses", [])},
        "xdp": [d for d in xdp if now.get(d, {}).get("xdp")],
        "wireguard": bool(config.wireguard.enabled and now.get(wireguard_iface(), {}).get("up")),
        "services": [u for u in EXPECTED_SERVICES if active(u)],
    }


def current_expectations() -> dict | None:
    """What works on this router now, for `stage` -- None without a
    config applied in full to read it against."""
    from frfw import provision

    applied = provision.load_applied_config()
    return None if applied is None else expectations(applied)


def expectation_problems(expect: dict, *, now: dict | None = None,
                         active: Callable[[str], bool] = service_active) -> list[str]:
    """What of `expect` doesn't work now."""
    now = network_now() if now is None else now
    problems = []
    for device in expect.get("carrier", []):
        if not now.get(device, {}).get("carrier"):
            problems.append(f"{device} had a link before the trial and has none now")
    for device, address in sorted((expect.get("addresses") or {}).items()):
        state = now.get(device, {})
        if address not in state.get("addresses", []) or not state.get("up"):
            problems.append(f"{device} is not up with its address {address}")
    for device in expect.get("xdp", []):
        if not now.get(device, {}).get("xdp"):
            problems.append(f"the XDP SNI filter is not attached to {device}")
    if expect.get("wireguard") and not now.get(wireguard_iface(), {}).get("up"):
        problems.append(f"the WireGuard tunnel {wireguard_iface()} is not up")
    for unit in expect.get("services", []):
        if not active(unit):
            problems.append(f"{unit} ran before the trial and is not running")
    return problems


def expectation_summary(expect: dict) -> str:
    """What a confirmed boot was checked for, for the journal."""
    parts = []
    if expect.get("carrier"):
        parts.append("links " + ", ".join(expect["carrier"]))
    if expect.get("addresses"):
        parts.append("addresses " + ", ".join(f"{d} {a}" for d, a in sorted(expect["addresses"].items())))
    if expect.get("xdp"):
        parts.append("XDP on " + ", ".join(expect["xdp"]))
    if expect.get("wireguard"):
        parts.append(wireguard_iface())
    if expect.get("services"):
        parts.append("services " + ", ".join(expect["services"]))
    return "; ".join(parts) or "nothing recorded"


def read_expect(boot_dir_path: Path) -> dict | None:
    try:
        data = json.loads((boot_dir_path / SLOT / EXPECT).read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def wireguard_iface() -> str:
    from frfw import wireguard

    return wireguard.IFACE


def wait_healthy(check: Callable[[], list[str]] = health_problems, *, timeout: float = HEALTH_TIMEOUT,
                 interval: float = 2.0, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> list[str]:
    """[] as soon as the check passes, else its problems at the deadline."""
    deadline = clock() + timeout
    while True:
        problems = check()
        if not problems or clock() >= deadline:
            return problems
        sleep(interval)


@dataclass
class Outcome:
    message: str
    alert: str | None = None  # a security alert to raise
    reboot: bool = False  # into the image's kernel: a failed trial


def confirm_boot(*, boot_dir_path: Path, cmdline: str | None = None,
                 wait: Callable[[], list[str]] | None = None) -> Outcome:
    """The step at the end of every boot GRUB started. Never raises for a
    state it doesn't expect: it says so and changes nothing. `wait`:
    wait_healthy."""
    expect = read_expect(boot_dir_path)
    wait = wait or wait_healthy
    mode = boot_mode(cmdline)
    env_path = boot_dir_path / ENV_NAME
    env = read_env(env_path)
    state, version = env.get(STATE), env.get(STAGED) or "?"

    if mode in (BOOT_TRIAL, BOOT_STAGED):
        expected = TRYING if mode == BOOT_TRIAL else BOOTING
        if state != expected:
            return Outcome(f"booted the staged kernel {version}, but its state is {state!r}, not {expected!r}: "
                           "left as it is")
        problems = wait()
        if not problems:
            write_env(env_path, {**env, STATE: GOOD})
            checked = (f"; what worked before it works: {expectation_summary(expect)}" if expect is not None
                       else "; checked against the applied config (no record of the moment it was staged)")
            return Outcome(f"kernel {version} confirmed: the router came up on it"
                           + (" (its trial boot)" if mode == BOOT_TRIAL else "") + checked)
        why = "; ".join(problems)
        if mode == BOOT_TRIAL:
            return Outcome(f"kernel {version} failed its trial boot ({why}): rebooting into the image's own kernel",
                           alert=f"kernel {version} failed its trial boot ({why}); the router reboots into the "
                                 "image's own kernel",
                           reboot=True)
        return Outcome(f"kernel {version} booted but the router is not up ({why}): the next boot uses the "
                       "image's own kernel",
                       alert=f"the router came up badly on kernel {version} ({why}); the next boot uses the "
                             "image's own kernel")

    if mode == BOOT_FALLBACK:
        return Outcome(f"kernel {version} did not come up; the image's own kernel booted instead",
                       alert=f"kernel {version} did not come up (a panic, a hang or a failed check, or its files "
                             "were damaged); the router booted the image's own kernel instead")

    if mode == BOOT_IMAGE and state in (TRYING, BOOTING):
        # GRUB chose the staged kernel, but the image's was picked from the
        # menu: the staged one wasn't tried, so it isn't a failure.
        restored = TRIAL if state == TRYING else GOOD
        write_env(env_path, {**env, STATE: restored})
        return Outcome(f"the image's kernel was chosen from the boot menu; kernel {version} stays {restored!r}")

    return Outcome("the image's own kernel" + (f"; kernel {version} is {state!r}" if state else ""))
