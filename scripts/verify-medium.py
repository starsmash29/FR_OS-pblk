#!/usr/bin/env python3
"""Check an FR_OS router's boot medium from another computer (ROADMAP SEC-15).

The router checks its own files too (Dashboard, System screen,
`firewall-cli integrity`), but whoever has root on it can change that
check as well. This one doesn't run on the router: shut it down, put its
USB stick (or an image of it) into another Linux computer, and run, from a
checkout of the FR_OS repository:

    sudo scripts/verify-medium.py /dev/sdX          # the router's stick
    sudo scripts/verify-medium.py fr_os-disk.img    # or an image of it

It mounts everything read-only -- the image (the squashfs on the stick)
and the persistence partition, whose `rw` directory holds every change
made since (updates included) -- puts them together the way the router
does, and compares FR_OS's files with the signed release of the version
found there, the same comparison as on the router (frfw.integrity). The
release's signature is checked with the public keys of *this checkout*
(src/frfw/release_keys/), never with keys from the stick -- or with
`--key`. `--release DIR` takes the release files (frfw-<v>.tar.gz,
SHA256SUMS, SHA256SUMS.sig) from DIR, e.g. downloaded from the GitHub
release, instead of the copies on the stick.

Already mounted (or for tests): `--lower DIR --upper DIR`, the image's
root and the persistence partition's `rw`.

Compiled files (.pyc) are checked only when this Python is the router's
(3.11 on Debian 12); otherwise they are counted and the result says so.

Exit status: 0 = every file matches the signed release, 1 = files were
changed, added or are missing, 2 = it could not be verified.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from frfw import integrity, release_signing  # noqa: E402

XDP_OBJECT = "/usr/local/share/fr_os/bpf/xdp_sni_filter.o"
RELEASES = "/opt/fr_os/releases"


class VerifyError(Exception):
    pass


def _run(*argv: str) -> str:
    proc = subprocess.run(list(argv), capture_output=True, text=True)
    if proc.returncode != 0:
        raise VerifyError(f"{' '.join(argv)}: {proc.stderr.strip() or proc.returncode}")
    return proc.stdout.strip()


@contextlib.contextmanager
def mounted_medium(target: Path):
    """(lower, upper) of a boot medium: the squashfs it boots, and its
    persistence partition's `rw` (an empty directory without one).
    Everything read-only, everything undone afterwards."""
    with tempfile.TemporaryDirectory(prefix="fros-verify-") as tmp:
        tmp = Path(tmp)
        loop = _run("losetup", "--read-only", "--find", "--show", "--partscan", str(target))
        mounts = []
        try:
            def mount(source: str, where: Path, *options: str) -> Path:
                where.mkdir()
                _run("mount", "-o", ",".join(("ro",) + options), source, str(where))
                mounts.append(where)
                return where

            # A hybrid ISO: its ISO 9660 filesystem starts at sector 0.
            iso = mount(loop, tmp / "iso")
            squashfs = iso / "live" / "filesystem.squashfs"
            if not squashfs.is_file():
                raise VerifyError(f"{target} has no live/filesystem.squashfs: not an FR_OS boot medium")
            lower = mount(str(squashfs), tmp / "lower", "loop")
            persistence = Path(f"{loop}p3")
            if not persistence.exists():
                subprocess.run(["partx", "--add", "--nr", "3", loop], capture_output=True)
            upper = tmp / "empty"
            upper.mkdir()
            if persistence.exists():
                upper = mount(str(persistence), tmp / "persistence") / "rw"
            yield lower, upper
        finally:
            for where in reversed(mounts):
                subprocess.run(["umount", str(where)], capture_output=True)
            subprocess.run(["losetup", "-d", loop], capture_output=True)


def verify(lower: Path, upper: Path, *, keys: list[Path], release_dir: Path | None = None) -> dict:
    view = integrity.OverlayView(lower, upper)
    package_dirs = sorted({str(p.relative_to(layer)) for layer in (upper, lower)
                           for p in layer.glob("usr/local/lib/python3*/dist-packages/frfw") if p.is_dir()})
    if not package_dirs:
        raise VerifyError("no FR_OS installation (usr/local/lib/python3*/dist-packages/frfw) on this medium")
    package_dir = "/" + package_dirs[-1]
    python = re.search(r"python3\.(\d+)", package_dir)
    pyc_tag = f"cpython-3{python.group(1)}"
    init = view.read(f"{package_dir}/__init__.py") or b""
    found = re.search(rb'__version__ = "([^"]+)"', init)
    if not found:
        raise VerifyError(f"{package_dir}/__init__.py names no version")
    version = found.group(1).decode()

    names = (release_signing.source_tarball_name(version), release_signing.SUMS_NAME,
             release_signing.SIGNATURE_NAME)
    with tempfile.TemporaryDirectory(prefix="fros-release-") as tmp:
        if release_dir is None:
            release_dir = Path(tmp)
            for name in names:
                data = view.read(f"{RELEASES}/{version}/{name}")
                if data is None:
                    raise VerifyError(f"the medium has no {name} for {version} under {RELEASES}: get the "
                                      "release from GitHub and pass --release DIR")
                (release_dir / name).write_bytes(data)
        tarball, sums, signature = (release_dir / n for n in names)
        try:
            key = release_signing.verify_release(tarball, sums, signature, name=names[0], keys=keys)
        except (release_signing.SignatureError, FileNotFoundError) as exc:
            raise VerifyError(f"the release of {version} does not verify: {exc}") from exc
        source = integrity.read_release(tarball, version)

    result = integrity.compare_with_release(view, source, package_dir=package_dir, xdp_object=XDP_OBJECT,
                                            pyc_tag=pyc_tag)
    return {
        "version": version,
        "key": key.name,
        "checked": result.checked,
        "modified": result.modified,
        "missing": result.missing,
        "added": result.added,
        "unchecked_pyc": result.unchecked_pyc,
        "pyc_tag": pyc_tag,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("medium", nargs="?", type=Path, help="the router's boot medium: a device or an image")
    parser.add_argument("--lower", type=Path, help="the image's root, already mounted")
    parser.add_argument("--upper", type=Path, help="the persistence partition's rw directory, already mounted")
    parser.add_argument("--key", type=Path, action="append",
                        help="a trusted release public key (default: this checkout's src/frfw/release_keys/)")
    parser.add_argument("--release", type=Path, help="take the release files from this directory")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)
    if (args.medium is None) == (args.lower is None):
        parser.error("give a medium, or --lower and --upper")
    keys = args.key or release_signing.trusted_keys()

    try:
        if args.medium is not None:
            with mounted_medium(args.medium) as (lower, upper):
                result = verify(lower, upper, keys=keys, release_dir=args.release)
        else:
            if args.upper is None:
                parser.error("--lower needs --upper")
            result = verify(args.lower, args.upper, keys=keys, release_dir=args.release)
    except VerifyError as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}))
        else:
            print(f"could not verify: {exc}", file=sys.stderr)
        return 2

    changed = result["modified"] or result["missing"] or result["added"]
    if args.json:
        print(json.dumps(result))
    else:
        print(f"FR_OS {result['version']}, release signed with {result['key']}: {result['checked']} files checked")
        for what in ("modified", "missing", "added"):
            for path in result[what]:
                print(f"  {what + ':':10} {path}")
        if result["unchecked_pyc"]:
            print(f"  {result['unchecked_pyc']} compiled files are for {result['pyc_tag']}, not this Python: "
                  "not checked (run this with the router's Python, 3.11, to check them too)")
        print("CHANGED: files of FR_OS don't match the signed release" if changed
              else "OK: every file matches the signed release")
    return 1 if changed else 0


if __name__ == "__main__":
    sys.exit(main())
