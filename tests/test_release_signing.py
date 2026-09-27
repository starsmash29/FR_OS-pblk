"""A4 (review triage): an update is installed only if it is signed.

Before, `frfw.update` downloaded GitHub's tag tarball over HTTPS and
`pip install`ed it as root with no signature or checksum check, and
reused a cached copy without checking it again. These tests use real
Ed25519 keys and signatures (the openssl CLI, as the router does).
"""

from __future__ import annotations

import io
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from frfw import release_signing, update as update_mod
from frfw.release_signing import SignatureError

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl CLI")

VERSION = "0.2.0"
TARBALL = release_signing.source_tarball_name(VERSION)


def _keypair(directory: Path, name: str) -> tuple[Path, Path]:
    private = directory / f"{name}.key"
    public = directory / f"{name}.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(private)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                   check=True, capture_output=True)
    return private, public


def _source_tarball(path: Path, marker: str = "genuine") -> None:
    with tarfile.open(path, "w:gz") as tar:
        for name, text in ((f"frfw-{VERSION}/pyproject.toml", "[project]\nname='frfw'\n"),
                           (f"frfw-{VERSION}/MARKER", marker)):
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def _sign(artifacts: Path, private: Path) -> None:
    digest = release_signing.sha256_of(artifacts / TARBALL)
    (artifacts / "SHA256SUMS").write_text(
        f"{digest}  FR_OS-{VERSION}-amd64.iso\n{digest}  {TARBALL}\n# a comment\n"
    )
    subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private),
                    "-in", str(artifacts / "SHA256SUMS"), "-out", str(artifacts / "SHA256SUMS.sig")],
                   check=True, capture_output=True)


@pytest.fixture
def keys(tmp_path):
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    trusted_private, trusted_public = _keypair(keys_dir, "trusted")
    other_private, _ = _keypair(tmp_path, "other")
    trusted_keys_dir = tmp_path / "release_keys"
    trusted_keys_dir.mkdir()
    shutil.copy(trusted_public, trusted_keys_dir / "fros-release-1.pem")
    return {"trusted": trusted_private, "other": other_private, "dir": trusted_keys_dir}


@pytest.fixture
def release(tmp_path, keys):
    artifacts = tmp_path / "published"
    artifacts.mkdir()
    _source_tarball(artifacts / TARBALL)
    _sign(artifacts, keys["trusted"])
    return artifacts


def _verify(artifacts: Path, keys_dir: Path):
    return release_signing.verify_release(
        artifacts / TARBALL, artifacts / "SHA256SUMS", artifacts / "SHA256SUMS.sig",
        name=TARBALL, keys=release_signing.trusted_keys(keys_dir),
    )


def test_a_genuine_release_verifies(release, keys):
    assert _verify(release, keys["dir"]).name == "fros-release-1.pem"


def test_a_tampered_tarball_is_refused(release, keys):
    _source_tarball(release / TARBALL, marker="evil")
    with pytest.raises(SignatureError, match="does not match the signed"):
        _verify(release, keys["dir"])


def test_a_tampered_checksum_file_is_refused(release, keys):
    _source_tarball(release / TARBALL, marker="evil")
    sums = release / "SHA256SUMS"
    sums.write_text(sums.read_text().replace(sums.read_text().split()[0],
                                             release_signing.sha256_of(release / TARBALL)))
    with pytest.raises(SignatureError, match="matches none"):
        _verify(release, keys["dir"])


def test_a_release_signed_with_an_unknown_key_is_refused(release, keys):
    _sign(release, keys["other"])
    with pytest.raises(SignatureError, match="matches none"):
        _verify(release, keys["dir"])


def test_no_trusted_key_means_no_update(release, tmp_path):
    with pytest.raises(SignatureError, match="trusts no release signing key"):
        _verify(release, tmp_path / "empty")


def test_a_checksum_file_without_the_tarball_is_refused(release, keys):
    with pytest.raises(SignatureError, match="lists no checksum"):
        release_signing.verify_release(
            release / TARBALL, release / "SHA256SUMS", release / "SHA256SUMS.sig",
            name="frfw-9.9.9.tar.gz", keys=release_signing.trusted_keys(keys["dir"]),
        )


# -- the updater itself ------------------------------------------------------------


@pytest.fixture
def updater(tmp_path, keys, monkeypatch):
    """frfw.update with its privileged steps recorded instead of run, the
    trusted keys pointed at the test's, and downloads served from a
    local "published" directory."""
    installed = []
    monkeypatch.setattr(release_signing, "TRUSTED_KEYS_DIR", keys["dir"])
    monkeypatch.setattr(update_mod, "_installed_version", lambda: "0.1.0")
    monkeypatch.setattr(update_mod, "_install_release_dir", lambda d: installed.append(d))
    monkeypatch.setattr(update_mod, "_restart_services", lambda services: None)
    monkeypatch.setattr(update_mod, "_restart_webui_delayed", lambda: None)
    downloads = []

    def serve_from(published: Path):
        def download(repo, tag, version, dest, timeout):
            downloads.append(tag)
            for name in (TARBALL, "SHA256SUMS", "SHA256SUMS.sig"):
                if (published / name).exists():
                    shutil.copy(published / name, dest / name)
                else:
                    raise update_mod.UpdateError(f"404 {name}")
        monkeypatch.setattr(update_mod, "_download_release_assets", download)

    return {"installed": installed, "downloads": downloads, "serve_from": serve_from,
            "state": tmp_path / "update_state.json", "releases": tmp_path / "releases"}


def _apply(updater):
    return update_mod.apply_update(VERSION, state_path=updater["state"], releases_dir=updater["releases"])


def test_the_updater_installs_a_signed_release(updater, release):
    updater["serve_from"](release)
    assert _apply(updater) == VERSION
    [source] = updater["installed"]
    assert (source / "MARKER").read_text() == "genuine"


def test_the_updater_refuses_an_unsigned_release_before_extracting(updater, release):
    (release / "SHA256SUMS.sig").unlink()
    updater["serve_from"](release)
    with pytest.raises(update_mod.UpdateError):
        _apply(updater)
    assert updater["installed"] == []
    assert not any(updater["releases"].glob("*/src"))


def test_the_updater_refuses_a_tampered_release(updater, release):
    _source_tarball(release / TARBALL, marker="evil")
    updater["serve_from"](release)
    with pytest.raises(update_mod.UpdateError, match="failed verification"):
        _apply(updater)
    assert updater["installed"] == []


def test_a_cached_release_is_verified_again(updater, release):
    """A rollback reuses the cache offline -- it must not trust it."""
    updater["serve_from"](release)
    _apply(updater)
    assert updater["downloads"] == ["v0.2.0"]
    _source_tarball(updater["releases"] / VERSION / TARBALL, marker="evil")  # the cache is swapped
    with pytest.raises(update_mod.UpdateError, match="failed verification"):
        update_mod._fetch_release(update_mod.DEFAULT_REPO, VERSION, updater["releases"], 5)
    assert updater["downloads"] == ["v0.2.0"]  # it was the cached copy that got refused


def test_the_package_ships_the_release_keys_directory():
    import tomllib

    pyproject = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    assert "release_keys/*.pem" in pyproject["tool"]["setuptools"]["package-data"]["frfw"]
