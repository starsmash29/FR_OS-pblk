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

from frfw import paths
from frfw.webui.app import create_app
from frfw.webui.tls import ensure_self_signed_cert


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

    app = create_app(config_path=Path(args.config))
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        ssl_certfile=str(cert_path),
        ssl_keyfile=str(key_path),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
