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
import csv
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
    # RECORD itself, not `dist.files`: since Python 3.12 that leaves out
    # every recorded file that no longer exists -- a deleted module would
    # go unreported on a newer Python.
    for row in csv.reader((dist.read_text("RECORD") or "").splitlines()):
        if len(row) < 2 or not row[1].startswith("sha256="):
            continue
        name, digest = row[0], row[1][len("sha256="):]
        checked += 1
        if name.startswith(f"{DISTRIBUTION}/") and name.endswith(".py"):
            has_module = True
        path = Path(dist.locate_file(name))
        try:
            if _sha256_b64(path) != digest:
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


# --- the rest of the persistence layer (ROADMAP SEC-22) --------------------


#: What a router writes on its persistence partition by itself, outside
#: FR_OS's own files: its config and state, logs, caches and leases, the
#: host keys and accounts first boot and live-config set up. Patterns over
#: the whole path, `*` within one name, `/**` a whole subtree. Taken from
#: the persistence layer after the boot test's boots, updates and kernel
#: trials (installer/qemu-boot-test.py checks that a clean run adds
#: nothing to it). The files of Debian named here are expected to change,
#: so their content is not judged: see ROADMAP SEC-22 for what that leaves.
PERSISTENCE_EXPECTED: tuple[str, ...] = (
    # FR_OS's config and state, and what it generates outside /etc/fr_os.
    "/etc/fr_os/**",
    "/etc/issue.d/fr_os-*.issue",
    "/etc/kea/kea-dhcp4.conf",
    "/etc/modules-load.d/fr_os-*.conf",
    "/etc/network/interfaces.d/fr_os-*",
    "/etc/ssh/sshd_config.d/*-fr_os-*.conf",
    "/var/lib/fr_os/**",
    # The system's identity, set at first boot (live-config, fr-first-boot).
    "/etc/hostname", "/etc/hosts", "/etc/machine-id", "/etc/resolv.conf",
    "/etc/timezone", "/etc/localtime", "/etc/fstab",
    "/etc/passwd", "/etc/passwd-", "/etc/group", "/etc/group-",
    "/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-", "/etc/.pwd.lock",
    "/etc/ssh/ssh_host_*_key", "/etc/ssh/ssh_host_*_key.pub",
    "/etc/ssh/sshd_config", "/etc/pam.d/login",
    "/etc/rc[06S].d/[KS]01hwclock.sh",
    # State, caches, leases and logs.
    "/var/cache/debconf/*",
    # Debian's daily timers on a router that stays up (logrotate, apt-daily,
    # dpkg-db-backup, man-db): seen or expected after the first days.
    "/var/lib/logrotate/status",
    "/var/backups/**",
    "/var/cache/apt/**", "/var/lib/apt/lists/**", "/var/lib/apt/periodic/**",
    "/var/cache/man/**",
    "/var/lib/dbus/machine-id",
    "/var/lib/dhcp/dhclient.*.leases",
    "/var/lib/kea/**",
    "/var/lib/live/config/*",
    "/var/lib/systemd/**",
    "/var/log/**",
    "/tmp/systemd-private-*/**", "/var/tmp/systemd-private-*/**",
    # Nothing under /root or /home: FR_OS has no console login, so a
    # shell's history there is someone else's too.
)

#: FR_OS's own files, compared with the signed release
#: (compare_with_release), and the signed releases themselves.
_OWN_TREES: tuple[str, ...] = (
    "/usr/local/lib/python3*/dist-packages/frfw/**",
    "/usr/local/share/fr_os/**",
    "/opt/fr_os/releases/**",
)

_WANTS = re.compile(rf"{re.escape(UNITS_DIR)}/[^/]+\.(?:wants|requires)/(?P<unit>[^/]+)\Z")


def release_targets(source: dict[str, bytes], *, xdp_object: str) -> set[str]:
    """Where the image and the updater install the release's files outside
    the Python package: the scripts, the units, the XDP program."""
    targets = set()
    for name in source:
        target = INSTALLED_FROM_SOURCE.get(name)
        if target is None and name.startswith("systemd/fr-") and "/" not in name[len("systemd/"):]:
            target = f"{UNITS_DIR}/{name[len('systemd/'):]}"
        if target is None and name == "bpf/xdp_sni_filter.o":
            target = xdp_object
        if target is not None:
            targets.add(target)
    return targets


@dataclass(frozen=True)
class PersistenceReport:
    #: ("added" | "changed" | "removed", path), by path.
    changes: list[tuple[str, str]]
    #: Debian's compiled files for the router's Python, when the Python
    #: comparing is another one: counted, not checked.
    unchecked_pyc: int = 0


def _path_matches(path: str, patterns: tuple[str, ...] | set[str]) -> bool:
    rel = PurePosixPath(path.lstrip("/"))
    for pattern in patterns:
        pattern = pattern.lstrip("/")
        if pattern.endswith("/**"):
            base = PurePosixPath(pattern[:-3])
            depth = len(base.parts)
            if len(rel.parts) > depth and _glob_match(PurePosixPath(*rel.parts[:depth]), str(base)):
                return True
        elif _glob_match(rel, pattern):
            return True
    return False


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return None


def _same_file(up: Path, a: os.stat_result, low: Path, b: os.stat_result) -> bool:
    """Whether the upper layer's entry is the image's own, copied up
    unchanged: same type, mode, owner, and content (or link target)."""
    if (a.st_mode, a.st_uid, a.st_gid) != (b.st_mode, b.st_uid, b.st_gid):
        return False
    if stat.S_ISDIR(a.st_mode):
        return True
    if stat.S_ISLNK(a.st_mode):
        return os.readlink(up) == os.readlink(low)
    if stat.S_ISREG(a.st_mode):
        if a.st_size != b.st_size:
            return False
        with up.open("rb") as fa, low.open("rb") as fb:
            while True:
                chunk = fa.read(1 << 20)
                if chunk != fb.read(1 << 20):
                    return False
                if not chunk:
                    return True
    return False  # a device, a pipe or a socket on the persistence layer


def persistence_changes(lower: Path | str, upper: Path | str, *, own_files: set[str],
                        pyc_tag: str | None = None,
                        expected: tuple[str, ...] = PERSISTENCE_EXPECTED) -> PersistenceReport:
    """What the persistence layer (`upper`) adds to, changes in or removes
    from the image (`lower`), outside FR_OS's own files (`own_files`, the
    release's targets, and _OWN_TREES) and what a router writes by itself.

    Review v0.2.1 #3: a root attacker's persistence -- a systemd unit,
    another program, an SSH key, a patched Debian file -- lives here, and
    the comparison with the signed release never looked. Both layers are
    untrusted (review v0.2.1 #2): everything is read with lstat, no link is
    followed, and a link is judged by the text of its target.

    The router's Python compiles Debian's modules on first use, into the
    persistence layer; such a `.pyc` is code it runs, so it must hold
    exactly the code compiled from the image's source (`pyc_tag` is the
    router's Python, cpython-311)."""
    lower, upper = Path(lower), Path(upper)
    pyc_tag = pyc_tag or sys.implementation.cache_tag
    own_units = {Path(p).name for p in own_files if p.startswith(UNITS_DIR + "/")}
    found: list[tuple[str, str]] = []
    unchecked_pyc = 0

    def judge(what: str, path: str) -> None:
        if not (_path_matches(path, expected) or _path_matches(path, _OWN_TREES) or path in own_files):
            found.append((what, path))

    view = OverlayView(lower, upper)

    def known(path: str, entry: Path, st: os.stat_result) -> bool:
        """An FR_OS unit enabled (a link to it in a .wants directory), or
        a compiled Debian module that holds its source's code."""
        nonlocal unchecked_pyc
        wants = _WANTS.match(path)
        if wants and stat.S_ISLNK(st.st_mode):
            unit = wants["unit"]
            return unit in own_units and os.readlink(entry) == f"{UNITS_DIR}/{unit}"
        rel = PurePosixPath(path)
        pyc = _PYC.match(rel.name)
        if not (pyc and rel.parent.name == "__pycache__" and stat.S_ISREG(st.st_mode)):
            return False
        source = PurePosixPath(*rel.parent.parent.parts[1:], f"{pyc['stem']}.py")
        if not view._lower_visible(source) or OverlayView._through_link(lower, source):
            return False
        low_source, up_source = lower / source, upper / source
        source_st = _lstat(low_source)
        if source_st is None or not stat.S_ISREG(source_st.st_mode) or _lstat(up_source) is not None:
            return False  # no source in the image, or one the upper layer changed (judged itself)
        if pyc["tag"] != pyc_tag:
            return False  # not the router's Python's: nothing there compiles it
        if pyc_tag != sys.implementation.cache_tag:
            unchecked_pyc += 1
            return True
        return _pyc_matches(entry.read_bytes(), low_source.read_bytes(), int(pyc["opt"] or 0))

    def walk(rel: PurePosixPath, lower_visible: bool) -> None:
        here = upper.joinpath(*rel.parts)
        for name in sorted(os.listdir(here)):
            entry, child = here / name, rel / name
            path = "/" + str(child)
            st = entry.lstat()
            low = lower.joinpath(*child.parts)
            # The image's entry, unless a link on the way (in the image) or
            # a whiteout or opaque directory above it (here) hides it.
            low_st = _lstat(low) if lower_visible and not OverlayView._through_link(lower, child) else None
            if OverlayView._whiteout(entry):
                if low_st is not None:
                    judge("removed", path)
                continue
            if stat.S_ISDIR(st.st_mode):
                opaque = OverlayView._opaque(entry)
                if low_st is not None and not stat.S_ISDIR(low_st.st_mode):
                    judge("changed", path)  # a file or link in the image
                elif low_st is not None and not _same_file(entry, st, low, low_st):
                    judge("changed", path + "/")  # its mode or owner
                if opaque and low_st is not None and stat.S_ISDIR(low_st.st_mode) and os.listdir(low):
                    judge("removed", path + "/")  # hides the image's files in it
                walk(child, lower_visible and not opaque and low_st is not None
                     and stat.S_ISDIR(low_st.st_mode))
                continue
            if low_st is not None and _same_file(entry, st, low, low_st):
                continue
            if known(path, entry, st):
                continue
            judge("added" if low_st is None else "changed", path)

    walk(PurePosixPath(), True)
    return PersistenceReport(sorted(found, key=lambda item: item[1]), unchecked_pyc)


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
