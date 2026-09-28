"""The WireGuard VPN (security-lessons G8/K5).

Remote access with keys instead of reusable passwords: a password typed
into a VPN portal can be sniffed on a compromised box and replayed
anywhere, a WireGuard key pair can't -- each device has its own, and the
router only ever knows the public half. It is also the safe way to
manage the router from outside (the tunnel's zone is a management zone
like the LAN), instead of opening the webUI to the internet
(management.allow_wan).

- The router's private key lives in /etc/fr_os/wireguard/private.key
  (0600 root, directory 0700), generated on the first apply that needs
  it. It is never in config.yaml, which the webUI can read.
- `sync` brings the kernel interface (wg0) in line with the config:
  created if missing, keys and peers loaded with `wg syncconf` (which
  keeps existing sessions), the tunnel address set, the link up -- or
  the interface removed when WireGuard is off. The private key reaches
  `wg` on its standard input, never through a file or the command line.
- The firewall side is in frfw.nft.builder: wg0 is in its zone's
  interface set, and the listen port is open on the input chain.

Shells out to `ip` and `wg` (wireguard-tools), like frfw.ifaddr.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from frfw import paths
from frfw.config.loader import internet_facing_zones
from frfw.config.schema import Config, WireguardConfig

#: The tunnel interface. One tunnel: every peer is a device of the
#: router's own users.
IFACE = "wg0"


class WireguardError(Exception):
    pass


@dataclass(frozen=True)
class SyncResult:
    message: str


Runner = Callable[..., subprocess.CompletedProcess]


def _run(argv: list[str], *, input: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=30)
    except FileNotFoundError as exc:
        tool = "wireguard-tools" if argv[0] == "wg" else "iproute2"
        raise WireguardError(f"{argv[0]!r} not found; install the {tool} package") from exc
    if check and proc.returncode != 0:
        raise WireguardError(proc.stderr.strip() or f"{argv[0]} exited with status {proc.returncode}")
    return proc


# -- keys ---------------------------------------------------------------------------


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def generate_keypair() -> tuple[str, str]:
    """A new (private, public) key pair, base64 like `wg genkey`/`wg pubkey`."""
    private = X25519PrivateKey.generate()
    raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
    return _b64(raw), public_key_of(_b64(raw))


def public_key_of(private_key: str) -> str:
    try:
        private = X25519PrivateKey.from_private_bytes(base64.b64decode(private_key, validate=True))
    except ValueError as exc:
        raise WireguardError("not a WireGuard private key") from exc
    return _b64(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def ensure_private_key(path: Path | None = None) -> str:
    """The router's private key, generated (0600, directory 0700) the
    first time it is needed."""
    path = path or paths.WIREGUARD_KEY_PATH
    try:
        key = path.read_text().strip()
        public_key_of(key)
        return key
    except FileNotFoundError:
        pass
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    key, _ = generate_keypair()
    tmp = path.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(key + "\n")
    tmp.replace(path)
    return key


def router_public_key(path: Path | None = None) -> str | None:
    """The router's public key, or None before the first apply made one."""
    path = path or paths.WIREGUARD_KEY_PATH
    try:
        return public_key_of(path.read_text().strip())
    except (OSError, WireguardError):
        return None


# -- configuration ---------------------------------------------------------------------


def render_conf(wg: WireguardConfig, private_key: str) -> str:
    """The `wg syncconf` configuration: keys, port and peers. (Addresses
    are the interface's business, set with `ip`.)"""
    lines = ["[Interface]", f"PrivateKey = {private_key}", f"ListenPort = {wg.listen_port}"]
    for peer in wg.peers:
        lines += ["", f"# {peer.name}", "[Peer]", f"PublicKey = {peer.public_key}", f"AllowedIPs = {peer.address}"]
    return "\n".join(lines) + "\n"


def tunnel_network(wg: WireguardConfig) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Interface(wg.address).network


def next_free_address(wg: WireguardConfig) -> str:
    """The first host address in the tunnel no peer (and not the router) uses."""
    used = {ipaddress.IPv4Interface(p.address).ip for p in wg.peers}
    used.add(ipaddress.IPv4Interface(wg.address).ip)
    for ip in tunnel_network(wg).hosts():
        if ip not in used:
            return f"{ip}/32"
    raise WireguardError(f"no free address left in {tunnel_network(wg)}")


def split_tunnel_networks(config: Config) -> list[str]:
    """What a client routes through the tunnel by default: the tunnel
    itself and the networks of the zones that don't face the internet."""
    internet = internet_facing_zones(config.zones, config.nat)
    nets = [str(tunnel_network(config.wireguard))]
    for iface in sorted(config.interfaces.values(), key=lambda i: i.name):
        if iface.address and iface.zone not in internet:
            net = str(ipaddress.IPv4Interface(iface.address).network)
            if net not in nets:
                nets.append(net)
    return nets


def client_config(config: Config, *, private_key: str, address: str, router_key: str,
                  full_tunnel: bool = False) -> str:
    """The configuration for a new device (the WireGuard app imports it,
    also as a QR code)."""
    wg = config.wireguard
    endpoint = wg.endpoint or "YOUR-ROUTER-ADDRESS"
    allowed = "0.0.0.0/0" if full_tunnel else ", ".join(split_tunnel_networks(config))
    return "\n".join([
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {address}",
        "",
        "[Peer]",
        f"PublicKey = {router_key}",
        f"Endpoint = {endpoint}:{wg.listen_port}",
        f"AllowedIPs = {allowed}",
        "PersistentKeepalive = 25",
        "",
    ])


# -- the kernel side -----------------------------------------------------------------------


def _link_exists(run: Runner) -> bool:
    return run(["ip", "link", "show", "dev", IFACE], check=False).returncode == 0


def sync(config: Config, *, dry_run: bool = False, key_path: Path | None = None,
         run: Runner | None = None) -> SyncResult:
    run = run or _run
    wg = config.wireguard
    if not wg.enabled:
        if dry_run:
            return SyncResult("WireGuard off (dry-run: nothing checked)")
        if _link_exists(run):
            run(["ip", "link", "del", "dev", IFACE])
            return SyncResult(f"WireGuard off: {IFACE} removed")
        return SyncResult("WireGuard off")
    summary = f"{IFACE} {wg.address}, UDP {wg.listen_port}, {len(wg.peers)} peer(s)"
    if dry_run:
        return SyncResult(f"WireGuard: would bring up {summary}")
    private_key = ensure_private_key(key_path)
    if not _link_exists(run):
        run(["ip", "link", "add", "dev", IFACE, "type", "wireguard"])
    # From standard input: the private key is never in a file wg could
    # leave behind, nor on a command line other users can read.
    run(["wg", "syncconf", IFACE, "/dev/stdin"], input=render_conf(wg, private_key))
    wanted = ipaddress.IPv4Interface(wg.address)
    shown = run(["ip", "-o", "-4", "addr", "show", "dev", IFACE]).stdout
    for line in shown.splitlines():
        parts = line.split()
        if "inet" in parts:
            current = parts[parts.index("inet") + 1]
            if ipaddress.IPv4Interface(current) != wanted:
                run(["ip", "addr", "del", current, "dev", IFACE])
    run(["ip", "addr", "replace", str(wanted), "dev", IFACE])
    run(["ip", "link", "set", "dev", IFACE, "up"])
    return SyncResult(f"WireGuard up: {summary}")


def status(*, key_path: Path | None = None, run: Runner | None = None) -> dict:
    """The router's public key and each peer's last handshake and traffic
    (`wg show wg0 dump`)."""
    run = run or _run
    result: dict = {"public_key": router_public_key(key_path), "up": False, "peers": {}}
    proc = run(["wg", "show", IFACE, "dump"], check=False)
    if proc.returncode != 0:
        return result
    result["up"] = True
    for line in proc.stdout.splitlines()[1:]:  # the first line is the interface
        fields = line.split("\t")
        if len(fields) < 7:
            continue
        result["peers"][fields[0]] = {
            "endpoint": "" if fields[2] == "(none)" else fields[2],
            "latest_handshake": int(fields[4] or 0),
            "rx_bytes": int(fields[5] or 0),
            "tx_bytes": int(fields[6] or 0),
        }
    return result
