"""Has the installed FR_OS software been changed? (security-lessons G9)

The FortiGate and PAN-OS intrusions kept access by patching files of the
firewall's own software. `pip install` records a SHA-256 of every file
it installs in the package's `RECORD`; this compares the files on disk
against it and reports anything modified or missing.

What it can and can't tell, honestly: it catches a changed or deleted
file (an implant in a module, a patched login check) and an accidental
corruption. It can't catch an attacker who has root and rewrites
`RECORD` too -- that needs a manifest signed with the release key (the
release tarball already is, see frfw.release_signing), which is future
work. A development install (`pip install -e`) has no hashes for the
modules, and is reported as not verifiable rather than as clean.
"""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path

DISTRIBUTION = "frfw"

#: The result is kept this long (a check hashes a few hundred files).
CACHE_SECONDS = 300

_cache: dict[str, tuple[float, "IntegrityReport"]] = {}


@dataclass(frozen=True)
class IntegrityReport:
    checked: int
    modified: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    verifiable: bool = True
    note: str = ""

    @property
    def ok(self) -> bool:
        return self.verifiable and not self.modified and not self.missing

    @property
    def summary(self) -> str:
        if not self.verifiable:
            return f"not verifiable: {self.note}"
        if self.ok:
            return f"all {self.checked} installed files match their recorded hashes"
        parts = []
        if self.modified:
            parts.append(f"{len(self.modified)} modified")
        if self.missing:
            parts.append(f"{len(self.missing)} missing")
        return f"{' and '.join(parts)} of {self.checked} installed files"


def _sha256_b64(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode()


def check(dist: metadata.Distribution | None = None) -> IntegrityReport:
    """Compare every file `dist` (default: the installed frfw) recorded
    with a hash against what is on disk now."""
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


def cached_check() -> IntegrityReport:
    now = time.monotonic()
    hit = _cache.get(DISTRIBUTION)
    if hit and now - hit[0] < CACHE_SECONDS:
        return hit[1]
    report = check()
    _cache[DISTRIBUTION] = (now, report)
    return report
