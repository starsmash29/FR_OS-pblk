"""`fr-webui`: uvicorn entry point serving the webUI over HTTPS.

Generates a self-signed cert on first run if none exists yet (see
frfw.webui.tls) so HTTPS works out of the box; binding :443 without root
is handled at the systemd level (AmbientCapabilities=CAP_NET_BIND_SERVICE
-- see systemd/fr-webui.service), not here.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import uvicorn

from frfw import paths, pqc
from frfw.config import ConfigError, load_config
from frfw.webui.app import create_app
from frfw.webui.tls import ensure_self_signed_cert


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fr-webui")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--cert", default=str(paths.WEBUI_CERT_PATH))
    parser.add_argument("--key", default=str(paths.WEBUI_KEY_PATH))
    parser.add_argument("--config", default=str(paths.CONFIG_PATH))
    args = parser.parse_args(argv)

    cert_path, key_path = Path(args.cert), Path(args.key)
    ensure_self_signed_cert(cert_path, key_path)

    config_path = Path(args.config)
    app = create_app(config_path=config_path)

    # The actual hybrid-group *preference* (X25519MLKEM768) comes from
    # the OPENSSL_CONF fragment fr-apply-helper maintains (see
    # frfw.pqc's module docstring for why that, and not something set
    # here, is the only mechanism that actually works) -- this only
    # covers the part of PQC hardening that *is* a supported
    # ssl.SSLContext setting: restricting the listener to TLS 1.3-only.
    ssl_context_factory = pqc.tls_ssl_context_factory if _pqc_enabled(config_path) else None

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        ssl_certfile=str(cert_path),
        ssl_keyfile=str(key_path),
        ssl_context_factory=ssl_context_factory,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
