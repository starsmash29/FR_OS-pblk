"""Has the installed FR_OS software been changed? (security-lessons G9, ROADMAP SEC-15)

The FortiGate and PAN-OS intrusions kept access by patching files of the
firewall's own software. This compares FR_OS's installed files with the
**signed release** they were installed from:

- the release is `frfw-<version>.tar.gz` with its `SHA256SUMS` and
  Ed25519 signature (frfw.release_signing), kept under
  `/opt/fr_os/releases/<version>/` -- by the image build since SEC-15
  (the CI signs the source before it builds the ISO) and by every update;
  the signature is checked again on every check;
- from the verified tarball it works out what must be on disk -- the
  installed package (what `pip install` puts there: the modules and the
  package data pyproject.toml names), the systemd units, the scripts and
  the compiled XDP program -- and compares it byte for byte;
- a module's compiled `.pyc` is code Python runs without looking at the
  `.py`: its code object must equal the one compiled from the signed
  source (a `.pyc` the router's own Python wouldn't load is not checked);
- a file in the package that the release doesn't have is reported, as
  added (an implant module).

pip's own `RECORD` (sha256 of every file it installed) is still checked
for what the release can't vouch for -- the console scripts and the
package metadata -- and is the whole check where there is no signed
release on the router (a development or local build).

What it can't do, said plainly: an attacker with root can also change
this module, or the public keys it trusts, and make it say anything. The
check that doesn't trust the router at all reads its boot medium from
another computer: `scripts/verify-medium.py` uses the same comparison,
with the public key of the checkout it runs from.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import importlib.util
import marshal
import os
import re
import stat
import sys
import tarfile
import time
import tomllib
from dataclasses import dataclass, field, replace
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Iterator

from frfw import paths, release_signing

DISTRIBUTION = "frfw"

#: The result is kept this long (a check reads the release and compares
#: a few hundred files).
CACHE_SECONDS = 300

_cache: dict[str, tuple[float, "IntegrityReport"]] = {}


@dataclass(frozen=True)
class IntegrityReport:
    checked: int
    modified: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    verifiable: bool = True
    note: str = ""
    #: What the files were compared with; "" is pip's install record.
    basis: str = ""
    #: Why the signed release itself didn't verify (then nothing is ok).
    signature_problem: str = ""

    @property
    def ok(self) -> bool:
        return (self.verifiable and not self.signature_problem
                and not self.modified and not self.missing and not self.added)

    @property
    def changes(self) -> list[str]:
        return self.modified + self.missing + self.added

    @property
    def summary(self) -> str:
        if not self.verifiable:
            return f"not verifiable: {self.note}"
        if self.signature_problem:
            return f"the signed release on this router does not verify: {self.signature_problem}"
        against = f" against {self.basis}" if self.basis else ""
        if self.ok:
            if self.basis:
                return f"all {self.checked} installed files match {self.basis}"
            return f"all {self.checked} installed files match their recorded hashes"
        parts = []
        for count, what in ((len(self.modified), "modified"), (len(self.missing), "missing"),
                            (len(self.added), "added")):
            if count:
                parts.append(f"{count} {what}")
        return f"{' and '.join(parts)} of {self.checked} installed files{against}"


# --- pip's install record --------------------------------------------------


def _sha256_b64(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode()


def check_record(dist: metadata.Distribution | None = None) -> IntegrityReport:
    """Compare every file `dist` (default: the installed frfw) recorded
    with a hash against what is on disk now -- pip's `RECORD`, which
    whoever has root can rewrite along with the files."""
    try:
        dist = dist or metadata.distribution(DISTRIBUTION)
    except metadata.PackageNotFoundError:
        return IntegrityReport(0, verifiable=False, note="the frfw package is not installed")
    checked, modified, missing = 0, [], []
    has_module = False
    for entry in dist.files or []:
        if entry.hash is None or entry.hash.mode != "sha256":
            continue
        checked += 1
        name = str(entry)
        if name.startswith(f"{DISTRIBUTION}/") and name.endswith(".py"):
            has_module = True
        path = Path(entry.locate())
        try:
            if _sha256_b64(path) != entry.hash.value:
                modified.append(name)
        except FileNotFoundError:
            missing.append(name)
        except OSError:
            modified.append(name)  # can't read it: don't call it clean
    if not has_module:
        return IntegrityReport(checked, modified, missing, verifiable=False,
                               note="a development install (pip install -e) records no module hashes")
    return IntegrityReport(checked, sorted(modified), sorted(missing))


# --- the files of a system -------------------------------------------------


class FileView:
    """The files of a system as `/`-rooted paths: this machine's, or (with
    `root`) a tree that stands for one."""

    def __init__(self, root: Path | str = "/") -> None:
        self.root = Path(root)

    def _host(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def read(self, path: str) -> bytes | None:
        try:
            return self._host(path).read_bytes()
        except (FileNotFoundError, NotADirectoryError, IsADirectoryError):
            return None

    def files(self, directory: str) -> Iterator[str]:
        """Every regular file under `directory`, as a `/`-rooted path."""
        base = self._host(directory)
        for dirpath, _dirs, names in os.walk(base):
            for name in names:
                host = Path(dirpath) / name
                if host.is_file() and not host.is_symlink():
                    yield "/" + str(host.relative_to(self.root))


class OverlayView(FileView):
    """A live-boot system seen from another computer: the image's files
    (`lower`, the squashfs) with the persistence partition's changes
    (`upper`, overlayfs' upper directory) on top -- a whiteout (a 0:0
    character device) deletes, an opaque directory hides the image's."""

    def __init__(self, lower: Path | str, upper: Path | str) -> None:
        super().__init__(lower)
        self.lower, self.upper = Path(lower), Path(upper)

    @staticmethod
    def _whiteout(path: Path) -> bool:
        try:
            st = path.lstat()
        except FileNotFoundError:
            return False
        return stat.S_ISCHR(st.st_mode) and st.st_rdev == 0

    @staticmethod
    def _opaque(path: Path) -> bool:
        try:
            return os.getxattr(path, "trusted.overlay.opaque") == b"y"
        except OSError:
            return False

    def _lower_visible(self, rel: PurePosixPath) -> bool:
        """Whether the image's copy of `rel` shows through the upper layer."""
        for i in range(1, len(rel.parts) + 1):
            up = self.upper.joinpath(*rel.parts[:i])
            if self._whiteout(up):
                return False
            if i < len(rel.parts) and self._opaque(up):
                return False
        return True

    @staticmethod
    def _through_link(layer: Path, rel: PurePosixPath) -> bool:
        """Whether a directory on the way to `rel` is a symlink. The
        medium is untrusted (scripts/verify-medium.py runs as root on
        another computer): a link like rw/usr -> / would make it read that
        computer's files (review v0.2.1 #2). Checked with lstat, so it
        holds where the mount can't refuse symlinks (nosymfollow)."""
        for i in range(1, len(rel.parts)):
            try:
                if stat.S_ISLNK(layer.joinpath(*rel.parts[:i]).lstat().st_mode):
                    return True
            except FileNotFoundError:
                return False
        return False

    def read(self, path: str) -> bytes | None:
        rel = PurePosixPath(path.lstrip("/"))
        up = self.upper / rel
        if self._through_link(self.upper, rel):
            return None
        if self._whiteout(up):
            return None
        if up.exists() or up.is_symlink():
            return up.read_bytes() if up.is_file() and not up.is_symlink() else None
        if not self._lower_visible(rel) or self._through_link(self.lower, rel):
            return None
        low = self.lower / rel
        if not low.is_file() or low.is_symlink():
            return None
        return low.read_bytes()

    def files(self, directory: str) -> Iterator[str]:
        seen = set()
        for layer in (self.upper, self.lower):
            base = layer / directory.lstrip("/")
            for dirpath, _dirs, names in os.walk(base):
                for name in names:
                    rel = PurePosixPath(Path(dirpath, name).relative_to(layer).as_posix())
                    if rel in seen:
                        continue
                    seen.add(rel)
                    if self.read("/" + str(rel)) is not None:
                        yield "/" + str(rel)


# --- the comparison with a signed release ----------------------------------


#: Files of the source tree the image and the updater install outside
#: the Python package (installer hook 0100-install-frfw, frfw.update).
#: Compared when they are on the system; the units are `systemd/fr-*`.
INSTALLED_FROM_SOURCE = {
    "scripts/fr-first-boot.sh": "/usr/local/sbin/fr-first-boot.sh",
    "scripts/install-system-integration.sh": "/usr/local/sbin/install-system-integration.sh",
    "systemd/journald-fr_os.conf": "/etc/systemd/journald.conf.d/fr_os.conf",
}
UNITS_DIR = "/etc/systemd/system"

#: The `.pyc` header of the Python comparing.
_MAGIC = importlib.util.MAGIC_NUMBER

_PYC = re.compile(r"(?P<stem>[^.]+)\.(?P<tag>[a-z]+-\d+)(?:\.opt-(?P<opt>[12]))?\.pyc\Z")


@dataclass(frozen=True)
class Comparison:
    checked: int
    modified: list[str]
    missing: list[str]
    added: list[str]
    #: Compiled files of another Python than the one comparing (offline).
    unchecked_pyc: int = 0


def read_release(tarball: Path, version: str) -> dict[str, bytes]:
    """The verified tarball's files, by their path inside the source tree."""
    prefix = f"frfw-{version.lstrip('v')}/"
    files = {}
    with tarfile.open(tarball, "r:gz") as tar:
        for member in tar:
            if member.isfile() and member.name.startswith(prefix):
                files[member.name[len(prefix):]] = tar.extractfile(member).read()
    return files


def installed_package_files(source: dict[str, bytes]) -> dict[str, bytes]:
    """What `pip install` puts in the package directory, from the source
    tree: every module of a package (a directory with `__init__.py`) and
    the files pyproject.toml's package-data names -- by path relative to
    the package directory (`frfw/...` -> `...`)."""
    package_data = tomllib.loads(source.get("pyproject.toml", b"").decode()).get(
        "tool", {}).get("setuptools", {}).get("package-data", {})
    packages = {str(PurePosixPath(name).parent) for name in source
                if name.startswith("src/frfw/") and name.endswith("/__init__.py")}
    wanted = {}
    for name, content in source.items():
        if not name.startswith("src/frfw/"):
            continue
        path = PurePosixPath(name)
        if name.endswith(".py") and str(path.parent) in packages:
            wanted[name[len("src/frfw/"):]] = content
            continue
        for package, globs in package_data.items():
            package_dir = PurePosixPath("src", *package.split("."))
            try:
                rel = path.relative_to(package_dir)
            except ValueError:
                continue
            if any(_glob_match(rel, g) for g in globs):
                wanted[name[len("src/frfw/"):]] = content
                break
    return wanted


def _glob_match(rel: PurePosixPath, pattern: str) -> bool:
    parts = pattern.split("/")
    return len(parts) == len(rel.parts) and all(fnmatch.fnmatchcase(p, g) for p, g in zip(rel.parts, parts))


def compare_with_release(view: FileView, source: dict[str, bytes], *, package_dir: str,
                         xdp_object: str, pyc_tag: str | None = None) -> Comparison:
    """Compare a system's FR_OS files with a release's verified source.
    `pyc_tag` is the cache tag of the Python on that system (cpython-311);
    compiled files of it are checked when the Python comparing is the
    same one, and only counted otherwise."""
    pyc_tag = pyc_tag or sys.implementation.cache_tag
    expected = installed_package_files(source)
    modified, missing, added = [], [], []
    checked = unchecked_pyc = 0

    for rel, content in sorted(expected.items()):
        path = f"{package_dir}/{rel}"
        on_disk = view.read(path)
        checked += 1
        if on_disk is None:
            missing.append(path)
        elif on_disk != content:
            modified.append(path)

    for path in sorted(view.files(package_dir)):
        rel = PurePosixPath(path[len(package_dir) + 1:])
        if str(rel) in expected:
            continue
        if rel.parent.name == "__pycache__":
            pyc = _PYC.match(rel.name)
            module = str(rel.parent.parent / f"{pyc['stem']}.py") if pyc else None
            if pyc and pyc["tag"] == pyc_tag and module in expected:
                if pyc_tag != sys.implementation.cache_tag:
                    unchecked_pyc += 1
                    continue
                checked += 1
                if not _pyc_matches(view.read(path) or b"", expected[module], int(pyc["opt"] or 0)):
                    modified.append(path)
                continue
            if pyc and pyc["tag"] != pyc_tag:
                continue  # another Python's: never loaded on this system
        added.append(path)

    for name, content in sorted(source.items()):
        target = INSTALLED_FROM_SOURCE.get(name)
        if target is None and name.startswith("systemd/fr-") and "/" not in name[len("systemd/"):]:
            target = f"{UNITS_DIR}/{name[len('systemd/'):]}"
        if target is None and name == "bpf/xdp_sni_filter.o":
            target = xdp_object
        if target is None:
            continue
        on_disk = view.read(target)
        if on_disk is None:
            if target == xdp_object:
                checked += 1
                missing.append(target)
            continue  # a unit or script this system never installed
        checked += 1
        if on_disk != content:
            modified.append(target)

    return Comparison(checked, modified, missing, added, unchecked_pyc)


def _pyc_matches(data: bytes, source: bytes, optimize: int) -> bool:
    """Whether a `.pyc` holds exactly the code compiled from `source`.
    Python runs a `.pyc` without reading the `.py` when its header fits,
    so a patched one is an implant the source never shows."""
    if len(data) < 16 or data[:4] != _MAGIC:
        return False
    try:
        code = marshal.loads(data[16:])
        return code == compile(source, "<signed source>", "exec", dont_inherit=True, optimize=optimize)
    except (ValueError, EOFError, TypeError, SyntaxError):
        return False


# --- this router -----------------------------------------------------------


def signed_release(version: str, releases_dir: Path | None = None) -> tuple[Path, Path, Path] | None:
    """The release files of `version` on this router, if they are there."""
    cache = (releases_dir or paths.RELEASES_DIR) / version.lstrip("v")
    files = (cache / release_signing.source_tarball_name(version), cache / release_signing.SUMS_NAME,
             cache / release_signing.SIGNATURE_NAME)
    return files if files[0].is_file() and files[1].is_file() else None


def check(*, releases_dir: Path | None = None, view: FileView | None = None,
          package_dir: Path | None = None, version: str | None = None,
          dist: metadata.Distribution | None = None) -> IntegrityReport:
    """This router's FR_OS files against the signed release of the
    running version -- or, without one, against pip's record."""
    from frfw import __version__

    version = version or __version__
    record = check_record(dist)
    release = signed_release(version, releases_dir)
    if release is None:
        return replace(record, note=record.note or f"no signed release of {version} on this router "
                       "(a development or local build): checked against pip's install record only")
    tarball, sums, signature = release
    if not signature.is_file():
        return replace(record, note=record.note or f"the release of {version} on this router is not signed "
                       "(a test build): checked against pip's install record only")
    try:
        key = release_signing.verify_release(tarball, sums, signature,
                                             name=release_signing.source_tarball_name(version))
    except release_signing.SignatureError as exc:
        return IntegrityReport(0, signature_problem=str(exc), basis=f"the signed release {version}")

    view = view or FileView()
    package_dir = str(package_dir or Path(__file__).resolve().parent)
    found = compare_with_release(view, read_release(tarball, version), package_dir=package_dir,
                                 xdp_object=str(paths.XDP_BPF_OBJ_PATH))
    # What the release can't vouch for -- pip's console scripts and the
    # package's metadata -- still against pip's record.
    outside = [n for n in record.modified + record.missing if not n.startswith(f"{DISTRIBUTION}/")]
    return IntegrityReport(
        found.checked,
        modified=sorted(found.modified + [n for n in outside if n in record.modified]),
        missing=sorted(found.missing + [n for n in outside if n in record.missing]),
        added=found.added,
        basis=f"the signed release {version} ({key.name})",
    )


def cached_check() -> IntegrityReport:
    now = time.monotonic()
    hit = _cache.get(DISTRIBUTION)
    if hit and now - hit[0] < CACHE_SECONDS:
        return hit[1]
    report = check()
    _cache[DISTRIBUTION] = (now, report)
    return report
