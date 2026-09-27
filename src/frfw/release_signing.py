"""Checking that a release really comes from FR_OS's maintainers.

An update runs `pip install` and rewrites systemd units as root, so the
code must be verified before anything is extracted or installed. Every
release publishes, next to the ISO:

- `frfw-<version>.tar.gz` -- the source (`git archive` of the tag);
- `SHA256SUMS` -- sha256 of the tarball and the ISO;
- `SHA256SUMS.sig` -- an Ed25519 signature over `SHA256SUMS`, made in CI
  with the private key held as the repository secret
  FROS_RELEASE_SIGNING_KEY (see docs/RELEASING.md).

The public keys this build trusts are the `*.pem` files shipped inside
the package (frfw/release_keys/). Verification uses the `openssl` CLI
(Ed25519 needs OpenSSL >= 3.0, as in Debian bookworm), so it adds no
Python dependency. Anything that doesn't verify -- no trusted key, a bad
signature, a missing or mismatching checksum -- is refused.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

#: Public keys (PEM, Ed25519) this build accepts release signatures from.
TRUSTED_KEYS_DIR = Path(__file__).with_name("release_keys")

SUMS_NAME = "SHA256SUMS"
SIGNATURE_NAME = "SHA256SUMS.sig"


class SignatureError(Exception):
    """A release failed verification; nothing from it may be used."""


def source_tarball_name(version: str) -> str:
    return f"frfw-{version.lstrip('v')}.tar.gz"


def trusted_keys(keys_dir: Path | None = None) -> list[Path]:
    keys_dir = TRUSTED_KEYS_DIR if keys_dir is None else keys_dir
    return sorted(keys_dir.glob("*.pem")) if keys_dir.is_dir() else []


def verify_signature(data: Path, signature: Path, keys: list[Path]) -> Path:
    """Return the key that signed `data`, or raise SignatureError."""
    if not keys:
        raise SignatureError(
            "this build trusts no release signing key (frfw/release_keys/ is empty), "
            "so it can't verify any update -- see docs/RELEASING.md"
        )
    for key in keys:
        try:
            proc = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(key), "-rawin",
                 "-in", str(data), "-sigfile", str(signature)],
                capture_output=True, text=True, timeout=30,
            )
        except FileNotFoundError as exc:
            raise SignatureError("openssl not found; can't verify the release signature") from exc
        if proc.returncode == 0:
            return key
    raise SignatureError(f"{data.name}: the signature matches none of the {len(keys)} trusted key(s)")


def expected_sha256(sums_text: str, name: str) -> str:
    """The checksum `SHA256SUMS` lists for `name` (sha256sum's format;
    `#` lines are comments)."""
    for line in sums_text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        digest, _, listed = line.strip().partition(" ")
        if listed.lstrip(" *") == name:
            return digest.lower()
    raise SignatureError(f"{SUMS_NAME} lists no checksum for {name}")


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_release(tarball: Path, sums: Path, signature: Path, *, name: str,
                   keys: list[Path] | None = None) -> Path:
    """Verify the signature over `sums`, then `tarball` against it.
    Returns the signing key; raises SignatureError on any mismatch."""
    key = verify_signature(sums, signature, trusted_keys() if keys is None else keys)
    want = expected_sha256(sums.read_text(), name)
    got = sha256_of(tarball)
    if got != want:
        raise SignatureError(f"{name}: sha256 {got} does not match the signed {SUMS_NAME} ({want})")
    return key
