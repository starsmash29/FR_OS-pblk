"""The updater refuses an older signed release, end to end (ROADMAP SEC-12).

Review v0.2.0 R18: an older release is signed as validly as it was the
day it came out, so the signature check alone let anyone who could get
one installed bring back what has been fixed since. Here the releases are
real -- `git archive` of this checkout, a SHA256SUMS and an Ed25519
signature made with a throwaway key (the release key never comes near a
test; trusted_keys() is pointed at the throwaway public key) -- and sit
verified in the updater's cache, so nothing but the version stands
between them and an install:

- an older one is refused, and nothing is extracted, installed or
  recorded;
- a newer one goes through the same real verification and extraction;
- the version this router updated from is still reachable by rollback.

Stood in: `pip`, `systemctl` and the unit staging (they would act on
this machine), as in tests/test_update_xdp_live.py.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from frfw import release_signing
from frfw import update as update_mod

REPO_ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None or shutil.which("git") is None, reason="needs openssl and git"
)


@pytest.fixture
def signer(tmp_path, monkeypatch):
    """A throwaway Ed25519 key, trusted for this test only; returns a
    function that puts a signed release of a version into a cache."""
    key = tmp_path / "throwaway.key"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)], check=True, capture_output=True)
    keys_dir = tmp_path / "trusted"
    keys_dir.mkdir()
    subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(keys_dir / "test-release.pem")],
                   check=True, capture_output=True)
    monkeypatch.setattr(release_signing, "TRUSTED_KEYS_DIR", keys_dir)

    def sign(releases_dir: Path, version: str) -> Path:
        cache = releases_dir / version
        cache.mkdir(parents=True)
        tarball = cache / release_signing.source_tarball_name(version)
        subprocess.run(["git", "-C", str(REPO_ROOT), "archive", "--format=tar.gz", "-o", str(tarball),
                        f"--prefix=frfw-{version}/", "HEAD"], check=True, capture_output=True)
        sums = cache / release_signing.SUMS_NAME
        sums.write_text(f"{release_signing.sha256_of(tarball)}  {tarball.name}\n")
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(sums),
                        "-out", str(cache / release_signing.SIGNATURE_NAME)], check=True, capture_output=True)
        return cache

    return sign


@pytest.fixture
def router(tmp_path, monkeypatch):
    """The updater on a router running 0.5.0, with pip and systemd stood in."""
    ran: list[list[str]] = []
    monkeypatch.setattr(update_mod, "_installed_version", lambda: "0.5.0")
    monkeypatch.setattr(update_mod, "_run", lambda argv: ran.append(argv))
    monkeypatch.setattr(update_mod, "_stage_systemd_units", lambda release_dir: None)
    return {"ran": ran, "state": tmp_path / "update_state.json", "releases": tmp_path / "releases"}


def test_an_older_signed_release_is_refused_and_nothing_is_touched(router, signer):
    cache = signer(router["releases"], "0.4.0")
    # It *is* a valid release: the signature and checksum check passes.
    update_mod._verify(cache, "0.4.0")

    with pytest.raises(update_mod.UpdateError, match="older than the installed 0.5.0"):
        update_mod.apply_update("0.4.0", state_path=router["state"], releases_dir=router["releases"])
    assert router["ran"] == [], "pip or systemctl ran for a refused downgrade"
    assert not (cache / "src").exists(), "the refused release was extracted"
    assert not router["state"].exists(), "a refused downgrade was recorded as an attempt"


def test_a_newer_signed_release_goes_through_and_the_way_back_is_rollback(router, signer, monkeypatch):
    signer(router["releases"], "0.4.0")
    signer(router["releases"], "0.6.0")
    assert update_mod.apply_update("0.6.0", state_path=router["state"], releases_dir=router["releases"]) == "0.6.0"
    assert (router["releases"] / "0.6.0" / "src").is_dir(), "the newer release was verified and extracted"
    assert any(argv[0] == "pip3" for argv in router["ran"])

    # Now on 0.6.0: 0.5.0 -- the version it updated from -- is reachable
    # by rollback only, and 0.4.0 not at all.
    monkeypatch.setattr(update_mod, "_installed_version", lambda: "0.6.0")
    signer(router["releases"], "0.5.0")
    for older in ("0.5.0", "0.4.0"):
        with pytest.raises(update_mod.UpdateError, match="older"):
            update_mod.apply_update(older, state_path=router["state"], releases_dir=router["releases"])
    assert update_mod.rollback_update(state_path=router["state"], releases_dir=router["releases"]) == "0.5.0"
    assert (router["releases"] / "0.5.0" / "src").is_dir()


def test_an_installed_release_stays_readable_for_the_integrity_check(router, signer):
    """ROADMAP SEC-15: the webUI (unprivileged) checks the installed files
    against the release the updater keeps -- readable whatever umask the
    updater runs with (a sandboxed unit may well set UMask=0077)."""
    import os
    import stat

    signer(router["releases"], "0.6.0")
    old = os.umask(0o077)
    try:
        update_mod.apply_update("0.6.0", state_path=router["state"], releases_dir=router["releases"])
    finally:
        os.umask(old)
    cache = router["releases"] / "0.6.0"
    assert stat.S_IMODE(cache.stat().st_mode) == 0o755
    for name in (release_signing.source_tarball_name("0.6.0"), release_signing.SUMS_NAME,
                 release_signing.SIGNATURE_NAME):
        assert stat.S_IMODE((cache / name).stat().st_mode) == 0o644, name
