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


AUTO_CERT_CN = "fr-router"


def _is_legacy_auto_cert(cert_path: Path) -> bool:
    """True for a certificate this module generated before phase 20: self-
    signed with CN=fr-router and no subjectAltName. Such a cert can't be
    verified by modern TLS clients (Go -- Prometheus, Grafana -- ignores the
    CN since Go 1.15), so it is replaced once. Anything else (an admin's own
    certificate) is never touched."""
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-subject", "-issuer", "-ext", "subjectAltName"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        return False
    if proc.returncode != 0:
        return False
    out = proc.stdout.replace(" ", "")
    return (
        f"subject=CN={AUTO_CERT_CN}" in out
        and f"issuer=CN={AUTO_CERT_CN}" in out
        and "SubjectAlternativeName" not in out
    )


def ensure_self_signed_cert(
    cert_path: Path,
    key_path: Path,
    *,
    common_name: str = AUTO_CERT_CN,
    dns_names: list[str] | None = None,
    ip_addresses: list[str] | None = None,
) -> bool:
    """Generate a self-signed cert/key pair if they don't already exist (or
    replace this module's own pre-phase-20 cert, see _is_legacy_auto_cert).

    The certificate carries subjectAltName entries -- `common_name`, any
    `dns_names` and `ip_addresses` -- because clients verify names against
    the SAN, not the CN: a Prometheus server scraping another site's
    /metrics with TLS verification (phase 20) checks it.

    Returns True if a new pair was generated, False if both already existed.
    """
    if cert_path.is_file() and key_path.is_file() and not _is_legacy_auto_cert(cert_path):
        return False

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        proc = subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "3650", "-subj", f"/CN={common_name}",
                "-addext", "subjectAltName=" + ",".join(
                    [f"DNS:{n}" for n in dict.fromkeys([common_name, *(dns_names or [])])]
                    + [f"IP:{ip}" for ip in dict.fromkeys(ip_addresses or [])]
                ),
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
