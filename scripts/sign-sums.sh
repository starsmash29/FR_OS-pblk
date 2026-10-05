#!/bin/sh
# Sign a SHA256SUMS file with the release key, in CI (docs/RELEASING.md).
#
#   SIGNING_KEY=<PEM> RELEASE_TAG=<tag or empty> scripts/sign-sums.sh DIR/SHA256SUMS
#
# Writes DIR/SHA256SUMS.sig (Ed25519, `openssl pkeyutl -rawin`), then
# checks it the way a router will: with the public keys this very commit
# ships (src/frfw/release_keys/) -- a release signed with any other key
# would be refused by every router, so it isn't published.
#
# Used twice by .github/workflows/build-installer.yml: for the source the
# image installs, before the ISO is built, so the image carries its own
# signed release (ROADMAP SEC-15, frfw.integrity); and for the published
# SHA256SUMS of the ISO and the source.
#
# Without SIGNING_KEY (the FROS_RELEASE_SIGNING_KEY secret) a test build
# stays unsigned -- but a release (RELEASE_TAG set) never does.
set -eu

sums="$1"
if [ -z "${SIGNING_KEY:-}" ]; then
    if [ -n "${RELEASE_TAG:-}" ]; then
        echo "::error::release_tag is set but the FROS_RELEASE_SIGNING_KEY secret is not -- refusing to publish an unsigned release (docs/RELEASING.md)"
        exit 1
    fi
    echo "::notice::no FROS_RELEASE_SIGNING_KEY secret: $sums stays unsigned (fine for a test build, not for a release)"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
umask 077
printf '%s\n' "$SIGNING_KEY" > "$work/release.key"
openssl pkeyutl -sign -rawin -inkey "$work/release.key" -in "$sums" -out "$sums.sig"
openssl pkey -in "$work/release.key" -pubout > "$work/release.pub"
rm -f "$work/release.key"
chmod 0644 "$sums.sig"

repo="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$repo/src" "$work/release.pub" "$sums" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from frfw.release_signing import trusted_keys, verify_signature
pub, sums = Path(sys.argv[2]).read_text(), Path(sys.argv[3])
if not any(k.read_text() == pub for k in trusted_keys()):
    sys.exit("::error::the signing key's public half is not in src/frfw/release_keys/")
print(f"{sums} signed by", verify_signature(sums, Path(f"{sums}.sig"), trusted_keys()).name)
PY
