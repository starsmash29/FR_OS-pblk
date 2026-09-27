"""`fr-webui`: uvicorn entry point serving the webUI over HTTPS.

Generates a self-signed cert on first run if none exists yet (see
frfw.webui.tls) so HTTPS works out of the box; binding :443 without root
is handled at the systemd level (AmbientCapabilities=CAP_NET_BIND_SERVICE
-- see systemd/fr-webui.service), not here.
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import ssl
import sys
from pathlib import Path

import uvicorn

from frfw import management, paths, pqc
from frfw.config import ConfigError, load_config
from frfw.webui.app import create_app
from frfw.webui.tls import ensure_self_signed_cert

#: linux/in.h; not exported by Python's socket module.
_IP_FREEBIND = getattr(socket, "IP_FREEBIND", 15)


def _pqc_enabled(config_path: Path) -> bool:
    """Whether to enforce TLS 1.3-only (`frfw.pqc.tls_ssl_context_factory`)
    for this run. Best-effort: a missing/invalid config must never stop
    the webUI from starting at all (an admin may need the webUI itself
    to fix a bad config), so this defaults to False -- the pre-existing,
    already-safe uvicorn TLS behavior -- rather than raising.
    """
    try:
        return load_config(config_path).pqc.enabled
    except (ConfigError, FileNotFoundError, OSError):
        return False


def _certificate_names(config_path: Path) -> tuple[list[str], list[str]]:
    """The router's hostname and static interface addresses, for the
    self-signed certificate's subjectAltName (best effort: an unreadable
    config just yields the default name)."""
    try:
        config = load_config(config_path)
    except (OSError, ConfigError):
        return [], []
    ips = [str(ipaddress.IPv4Interface(i.address).ip) for i in config.interfaces.values() if i.address]
    return [config.hostname], ips


def tls_minimum_1_2_context_factory(uvicorn_config: object, default_factory) -> ssl.SSLContext:
    """Security-lessons H2: TLS 1.2 is the floor, stated explicitly rather
    than left to whatever the Python/OpenSSL build defaults to. (With PQC
    on, frfw.pqc's factory makes it TLS 1.3-only instead.)"""
    ctx = default_factory()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def listen_addresses(config_path: Path) -> list[str]:
    """Security-lessons F2/G4: loopback and the management zones'
    addresses (frfw.management), never 0.0.0.0 unless management.allow_wan
    says so. Without a readable config: loopback only -- the console is
    the way in then, not the network."""
    try:
        config = load_config(config_path)
    except (OSError, ConfigError):
        return [management.LOOPBACK]
    if config.management.allow_wan:
        print(f"fr-webui: WARNING: {management.WAN_WARNING}", file=sys.stderr, flush=True)
    return management.listen_addresses(config)


def bind_sockets(addresses: list[str], port: int) -> list[socket.socket]:
    """One listening socket per address. IP_FREEBIND lets it bind an
    address that isn't on an interface yet (a LAN port still coming up)
    instead of failing."""
    sockets = []
    for address in addresses:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, _IP_FREEBIND, 1)
        sock.bind((address, port))
        sock.listen(2048)
        sock.set_inheritable(True)
        sockets.append(sock)
    return sockets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fr-webui")
    parser.add_argument("--host", action="append",
                        help="listen on this address (repeatable); default: the management addresses from the config")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--cert", default=str(paths.WEBUI_CERT_PATH))
    parser.add_argument("--key", default=str(paths.WEBUI_KEY_PATH))
    parser.add_argument("--config", default=str(paths.CONFIG_PATH))
    args = parser.parse_args(argv)

    cert_path, key_path = Path(args.cert), Path(args.key)
    config_path = Path(args.config)
    dns_names, ip_addresses = _certificate_names(config_path)
    ensure_self_signed_cert(cert_path, key_path, dns_names=dns_names, ip_addresses=ip_addresses)

    app = create_app(config_path=config_path, webui_cert_path=cert_path)

    # The actual hybrid-group *preference* (X25519MLKEM768) comes from
    # the OPENSSL_CONF fragment fr-apply-helper maintains (see
    # frfw.pqc's module docstring for why that, and not something set
    # here, is the only mechanism that actually works) -- this only
    # covers the part of PQC hardening that *is* a supported
    # ssl.SSLContext setting: restricting the listener to TLS 1.3-only.
    ssl_context_factory = (
        pqc.tls_ssl_context_factory if _pqc_enabled(config_path) else tls_minimum_1_2_context_factory
    )

    addresses = args.host or listen_addresses(config_path)
    print(f"fr-webui: listening on {', '.join(addresses)} port {args.port}", file=sys.stderr, flush=True)
    server = uvicorn.Server(uvicorn.Config(
        app,
        port=args.port,
        ssl_certfile=str(cert_path),
        ssl_keyfile=str(key_path),
        ssl_context_factory=ssl_context_factory,
    ))
    server.run(sockets=bind_sockets(addresses, args.port))
    return 0


if __name__ == "__main__":
    sys.exit(main())
