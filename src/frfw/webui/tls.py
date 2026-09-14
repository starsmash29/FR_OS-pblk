"""Bootstraps a self-signed TLS cert for the webUI's first run.

Shells out to `openssl` (present on any Debian box) rather than adding
the `cryptography` package -- a compiled extension -- as a dependency
just to generate one keypair. A real router should get a proper cert
(ACME/Let's Encrypt with a real domain, or an internal CA) once one is
available; this only exists so HTTPS works out of the box before that.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


class TlsError(Exception):
    pass


def ensure_self_signed_cert(
    cert_path: Path, key_path: Path, *, common_name: str = "fr-router"
) -> bool:
    """Generate a self-signed cert/key pair if they don't already exist.

    Returns True if a new pair was generated, False if both already existed.
    """
    if cert_path.is_file() and key_path.is_file():
        return False

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        proc = subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "3650", "-subj", f"/CN={common_name}",
            ],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise TlsError("'openssl' binary not found; install the openssl package") from exc

    if proc.returncode != 0:
        raise TlsError(proc.stderr.strip() or "openssl failed to generate a certificate")

    key_path.chmod(0o600)
    return True
