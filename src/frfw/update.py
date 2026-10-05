"""System update mechanism (phase 6, see ROADMAP.md).

Two clearly separate halves, matching the security-model split used
throughout the rest of frfw:

- **Checking** for a new version (`check_latest`, `list_releases`) is a
  read-only HTTPS GET to GitHub's Releases API. It needs no privilege at
  all and is called fresh, in-process, on every webUI page load (same
  pattern as the AI IDS screen's live-computed progress) -- there is no
  persisted "last checked" state, because there is nothing worth caching
  for a request this cheap.

- **Applying** an update or rolling back (`apply_update`,
  `rollback_update`) genuinely needs root: it downloads and extracts a
  release tarball, `pip install`s it, rewrites systemd units and
  restarts services. This half is only ever invoked from the privileged
  fr-update-helper daemon (`frfw.helper.update_server`) or directly by
  an admin running `firewall-cli update apply/rollback` as root over
  SSH -- never from the unprivileged webUI process itself.

The update *source* is this project's own GitHub repo (`DEFAULT_REPO`,
overridable via config.yaml's `update.repo` for a fork/community
edition). A release is identified by a `vMAJOR.MINOR.PATCH` git tag;
"installing" it means downloading that release's source tarball, its
`SHA256SUMS` and `SHA256SUMS.sig` (release assets), verifying them
against the public keys shipped in *this* build (frfw.release_signing)
and only then extracting and `pip install`ing it. An unsigned release, a
signature from an unknown key or a tarball that doesn't match the signed
checksum is refused before anything is extracted -- also when it comes
from the local cache (a rollback re-verifies).

Still trusted without verification: the Python dependencies `pip`
resolves from PyPI for the release (`>=` floors in pyproject.toml).

Updates only go forward: `apply_update` refuses a version older than
(or the same as) the installed one, however validly it is signed -- an
old release brings back what has been fixed since (ROADMAP SEC-12).

Rollback is the one way back, and a single level deep: applying an
update remembers the version you were on as `previous_version`; rolling
back reinstalls that version and clears it, so rolling back a rollback
is not supported. If a
release's extracted source is still present under `RELEASES_DIR` (which
successful updates never delete), rollback reuses it directly with no
network access needed -- useful precisely when the update that broke
something also broke connectivity.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from frfw import __version__, paths, release_signing, validate

#: This project's own repo; checked/installed from unless config.yaml's
#: `update.repo` overrides it (see frfw.config.schema.UpdateConfig).
DEFAULT_REPO = "starsmash29/FR_OS-pblk"

#: systemd units restarted after a successful install, so the new code
#: actually takes effect. Deliberately excludes fr-update-helper.service
#: itself: restarting the very service that is executing this update
#: from within its own request handler would kill the process before it
#: can send its response back to the caller. That daemon's own code only
#: picks up an update on its next natural restart (reboot, or a manual
#: `systemctl restart fr-update-helper`) -- a real, documented
#: limitation rather than an oversight.
SERVICES_TO_RESTART: tuple[str, ...] = (
    # First: a release may change the accounts and groups the others run
    # as (ROADMAP SEC-11 moved the sensors out of the webUI's group), and
    # this oneshot is what makes them so.
    "fr-accounts.service",
    "fr-apply-helper.service",
    "fr-firewall.service",
    # After fr-firewall, whose apply writes their config copy: the parser
    # daemons come back with the release's code and with the groups
    # fr-accounts just gave them -- their old processes keep the old ones,
    # and would lose the helper socket and the event feeds (ROADMAP SEC-11).
    "fr-ai-ids.service",
    "fr-appid.service",
    "fr-tls-fp.service",
)

#: fr-webui.service is restarted separately, and deliberately delayed
#: (see _restart_webui_delayed): it is the very process that received
#: the webUI request that triggered this update, so restarting it
#: synchronously would sever that connection before the browser ever
#: saw a response.
WEBUI_SERVICE = "fr-webui.service"
_WEBUI_RESTART_DELAY_SECONDS = 3

#: systemd unit files never touched by an update: fr-first-boot has
#: already done its one-time job and must never re-trigger, and
#: fr-update-helper is excluded for the reason in SERVICES_TO_RESTART's
#: docstring above (its *unit file* is still refreshed, just not
#: restarted).
_UNIT_FILES_NOT_RESTARTED = frozenset({"fr-first-boot.service"})

_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)\Z")


class UpdateError(Exception):
    """Raised for any update-check, update-apply or rollback failure."""


@dataclass(frozen=True)
class ReleaseInfo:
    """One GitHub release, as needed for the changelog/version-check UI."""

    tag: str
    version: str
    notes: str
    published_at: str | None = None
    html_url: str = ""
    #: A security release (security-lessons G10): "[security]" in the
    #: release title, or a "Security: yes" line in its notes. See
    #: docs/RELEASING.md.
    security: bool = False


@dataclass(frozen=True)
class UpdateCheckResult:
    current_version: str
    latest: ReleaseInfo | None
    update_available: bool
    checked_at: str


@dataclass
class UpdateState:
    """Persisted apply/rollback history -- see paths.UPDATE_STATE_PATH."""

    current_version: str
    previous_version: str | None = None
    last_update: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "current_version": self.current_version,
            "previous_version": self.previous_version,
            "last_update": self.last_update,
        }

    @classmethod
    def from_dict(cls, data: dict, *, current_version: str) -> "UpdateState":
        return cls(
            current_version=current_version,
            previous_version=data.get("previous_version"),
            last_update=data.get("last_update") or {},
        )


def parse_version(text: str) -> tuple[int, int, int]:
    """Parse a `vMAJOR.MINOR.PATCH` (or bare `MAJOR.MINOR.PATCH`) string.

    Raises `UpdateError` (not `ValueError`) so callers already catching
    the module's own exception type don't need a second `except`.
    """
    # No .strip(): a version with whitespace or a newline in it is not one
    # (security-lessons F1) -- it names directories removed and installed as root.
    match = _VERSION_RE.match(text) if isinstance(text, str) else None
    if not match:
        raise UpdateError(f"not a recognized vMAJOR.MINOR.PATCH version: {text!r}")
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def load_state(
    *, current_version: str, path: Path = paths.UPDATE_STATE_PATH
) -> UpdateState:
    """Read the persisted update history, if any.

    `current_version` always wins over whatever the file says -- it
    reflects what is actually `pip`-installed right now, which is the
    only thing that can't drift out of sync with reality.
    """
    if not path.exists():
        return UpdateState(current_version=current_version)
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return UpdateState(current_version=current_version)
    if not isinstance(data, dict):
        return UpdateState(current_version=current_version)
    return UpdateState.from_dict(data, current_version=current_version)


def save_state(state: UpdateState, path: Path = paths.UPDATE_STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(state.to_dict(), indent=2) + "\n")
    tmp_path.replace(path)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fetch_json(url: str, timeout: float) -> object:
    """The one seam every network call in this module goes through, so
    tests can monkeypatch a single function instead of mocking sockets."""
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "fr_os-update"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError:
        raise
    except urllib.error.URLError as exc:
        raise UpdateError(f"could not reach {url}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise UpdateError(f"invalid JSON from {url}: {exc}") from exc


_SECURITY_LINE = re.compile(r"^\s*security:\s*yes\s*$", re.I | re.M)


def is_security_release(name: str, notes: str) -> bool:
    return "[security]" in name.lower() or bool(_SECURITY_LINE.search(notes))


def _release_from_json(raw: dict) -> ReleaseInfo:
    tag = str(raw.get("tag_name") or "")
    notes = str(raw.get("body") or "")
    return ReleaseInfo(
        tag=tag,
        version=tag[1:] if tag.startswith("v") else tag,
        notes=notes,
        published_at=raw.get("published_at"),
        html_url=str(raw.get("html_url") or ""),
        security=is_security_release(str(raw.get("name") or ""), notes),
    )


# -- the periodic check (security-lessons G10/J3) ------------------------------------


def write_check_cache(result: UpdateCheckResult, path: Path | None = None, *,
                      error: str | None = None, auto_install_error: str | None = None) -> None:
    """What the last periodic check found, for the webUI's banner (the
    webUI itself doesn't have to reach GitHub to know). 0644: it holds
    nothing secret."""
    latest = result.latest
    data = {
        "checked_at": result.checked_at,
        "current_version": result.current_version,
        "update_available": result.update_available,
        "latest_version": latest.version if latest else None,
        "security": bool(latest and latest.security and result.update_available),
        "html_url": latest.html_url if latest else "",
        "error": error,
        # J3: the automatic install of this security release failed.
        "auto_install_error": auto_install_error,
    }
    write_json_cache(data, path)


def write_json_cache(data: dict, path: Path | None = None) -> None:
    path = path or paths.UPDATE_CHECK_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.chmod(0o644)
    tmp.replace(path)


def read_check_cache(path: Path | None = None, *, current_version: str | None = None) -> dict | None:
    """The cached check, or None -- also when it is about a version that is
    no longer the installed one (an update happened since)."""
    path = path or paths.UPDATE_CHECK_PATH
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if current_version is not None and data.get("current_version") != current_version:
        return None
    return data


def list_releases(
    repo: str = DEFAULT_REPO, limit: int = 10, timeout: float = 10.0
) -> list[ReleaseInfo]:
    """Most recent releases (newest first), for a changelog display."""
    try:
        raw = _fetch_json(
            f"https://api.github.com/repos/{_checked_repo(repo)}/releases?per_page={int(limit)}", timeout
        )
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise UpdateError(f"GitHub returned {exc.code} listing releases for {repo}") from exc
    if not isinstance(raw, list):
        raise UpdateError(f"unexpected releases response from GitHub for {repo}")
    return [_release_from_json(item) for item in raw if isinstance(item, dict)]


def check_latest(
    current_version: str, repo: str = DEFAULT_REPO, timeout: float = 10.0
) -> UpdateCheckResult:
    """Compare `current_version` against the repo's latest GitHub release.

    A repo with no releases published yet (a real, expected state for
    this project pre-1.0) is reported as "no update available" rather
    than an error -- GitHub's own API returns a plain 404 for that case.
    """
    checked_at = _now()
    try:
        raw = _fetch_json(f"https://api.github.com/repos/{_checked_repo(repo)}/releases/latest", timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return UpdateCheckResult(
                current_version=current_version,
                latest=None,
                update_available=False,
                checked_at=checked_at,
            )
        raise UpdateError(f"GitHub returned {exc.code} checking {repo}") from exc

    if not isinstance(raw, dict):
        raise UpdateError(f"unexpected release response from GitHub for {repo}")
    latest = _release_from_json(raw)

    try:
        update_available = parse_version(latest.version) > parse_version(current_version)
    except UpdateError:
        # Non-semver tag on either side: fall back to "different means new"
        # rather than refusing to ever report an update.
        update_available = bool(latest.version) and latest.version != current_version

    return UpdateCheckResult(
        current_version=current_version,
        latest=latest,
        update_available=update_available,
        checked_at=checked_at,
    )


def _run(cmd: list[str]) -> None:
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        raise UpdateError(f"`{' '.join(cmd)}` failed: {detail}") from exc
    except FileNotFoundError as exc:
        raise UpdateError(f"`{cmd[0]}` not found: {exc}") from exc


def _download(url: str, dest: Path, timeout: float) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "fr_os-update"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            with dest.open("wb") as f:
                shutil.copyfileobj(response, f)
    except urllib.error.URLError as exc:
        raise UpdateError(f"could not download {url}: {exc}") from exc


def _checked_repo(repo: str) -> str:
    """Security-lessons F1: `update.repo` goes into URLs the root updater
    fetches code from -- only a plain OWNER/NAME."""
    try:
        return validate.github_repo(repo)
    except validate.ArgumentError as exc:
        raise UpdateError(str(exc)) from exc


def _download_release_assets(repo: str, tag: str, version: str, dest: Path, timeout: float) -> None:
    """The source tarball and the signed checksums, from the release."""
    base = f"https://github.com/{_checked_repo(repo)}/releases/download/{tag}"
    for name in (release_signing.source_tarball_name(version), release_signing.SUMS_NAME,
                 release_signing.SIGNATURE_NAME):
        _download(f"{base}/{name}", dest / name, timeout)


def _safe_extract(tarball: Path, dest: Path) -> Path:
    """Extract `tarball` into `dest`, refusing any member that would
    escape it (a corrupt or malicious tarball's `../` path traversal).

    Works uniformly across the Python versions this project supports;
    `tarfile.extractall`'s own `filter=` path-safety argument only
    exists from 3.12 on (this project targets >=3.11), so this checks
    every member's resolved path by hand instead of relying on it.
    """
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()
    with tarfile.open(tarball) as tar:
        # Only regular files and directories: an update installs nothing
        # else. The source tree's links -- live-build's bootloader links,
        # which point into the build host's /usr/lib -- are skipped, never
        # created: filter="data" refuses an absolute link (every update
        # failed on them, found by tests/test_update_xdp_live.py), and
        # without that filter a link's *target* is not checked by the
        # loop below at all.
        members = [m for m in tar.getmembers() if m.isfile() or m.isdir()]
        for member in members:
            target = (dest / member.name).resolve()
            if target != dest_resolved and dest_resolved not in target.parents:
                raise UpdateError(
                    f"refusing to extract {member.name!r}: escapes {dest}"
                )
        try:
            # filter="data" (Python 3.12+) adds further hardening (device
            # files, permission bits) on top of the path check above;
            # 3.11 (this project's minimum) has no such parameter.
            tar.extractall(dest, members=members, filter="data")
        except TypeError:
            tar.extractall(dest, members=members)  # noqa: S202 -- members validated above

    entries = [p for p in dest.iterdir() if p.is_dir()]
    if len(entries) != 1:
        raise UpdateError(f"unexpected release archive layout under {dest}")
    return entries[0]


def _verify(artifacts: Path, version: str) -> None:
    name = release_signing.source_tarball_name(version)
    try:
        release_signing.verify_release(
            artifacts / name,
            artifacts / release_signing.SUMS_NAME,
            artifacts / release_signing.SIGNATURE_NAME,
            name=name,
        )
    except (release_signing.SignatureError, OSError) as exc:
        raise UpdateError(f"release {version} failed verification, not installing it: {exc}") from exc


def _fetch_release(repo: str, version: str, releases_dir: Path, timeout: float) -> Path:
    """Return a local directory containing `version`'s verified source.

    `releases_dir/<version>/` keeps the downloaded tarball, SHA256SUMS
    and signature (so a rollback works offline) and, under `src/`, what
    was extracted from them. The signature is checked every time, also
    for a cached copy, and the source re-extracted from the verified
    tarball -- never trusted just because it is on disk.
    """
    releases_dir.mkdir(parents=True, exist_ok=True)
    cache = releases_dir / version
    tag = version if version.startswith("v") else f"v{version}"
    with tempfile.TemporaryDirectory(dir=releases_dir) as tmp:
        tmp_path = Path(tmp)
        artifacts = tmp_path / "artifacts"
        artifacts.mkdir()
        cached = [cache / n for n in (release_signing.source_tarball_name(version),
                                      release_signing.SUMS_NAME, release_signing.SIGNATURE_NAME)]
        if all(p.is_file() for p in cached):
            for p in cached:
                shutil.copy2(p, artifacts / p.name)
        else:
            _download_release_assets(repo, tag, version, artifacts, timeout)
        _verify(artifacts, version)
        _safe_extract(artifacts / release_signing.source_tarball_name(version), artifacts / "src")

        if cache.exists():
            shutil.rmtree(cache)
        shutil.move(str(artifacts), str(cache))
    # Readable by everyone, like any published release: the webUI checks
    # the installed files against it (ROADMAP SEC-15, frfw.integrity).
    # The temporary directory it was made in is 0700.
    cache.chmod(0o755)
    for name in cached:
        (cache / name.name).chmod(0o644)

    return next(p for p in (cache / "src").iterdir() if p.is_dir())


def _stage_systemd_units(release_dir: Path) -> None:
    systemd_src = release_dir / "systemd"
    systemd_dest = Path("/etc/systemd/system")
    if not systemd_src.is_dir():
        return
    for unit_file in sorted(systemd_src.glob("fr-*")):
        shutil.copy2(unit_file, systemd_dest / unit_file.name)

    for script_name in ("fr-first-boot.sh", "install-system-integration.sh"):
        src = release_dir / "scripts" / script_name
        if src.is_file():
            dest = Path("/usr/local/sbin") / script_name
            shutil.copy2(src, dest)
            dest.chmod(0o755)


#: The release's hash-pinned dependencies (review FR-001).
LOCK_FILE = "requirements.lock"

#: The release's compiled XDP SNI filter, added to the signed tarball by
#: the release build (ROADMAP P4-1, scripts/build-xdp-object.sh).
XDP_OBJECT = Path("bpf") / "xdp_sni_filter.o"


def _install_xdp_object(release_dir: Path, dest: Path) -> None:
    """Put the release's compiled XDP program where frfw.xdp loads it
    from, replacing the previous release's (ROADMAP P4-1). A router never
    compiles it, so without this an update kept running the old program:
    the new source was never looked at, and the unchanged object gave
    SEC-19's digest check nothing to notice. The next apply (fr-firewall
    restarts below) sees the new digest and swaps the program in.

    A release built before P4-1 has no object: the previous one is
    removed rather than left to run under code it wasn't built for, and
    turning the filter on says there is no compiled program -- as on
    every image of those releases."""
    obj = release_dir / XDP_OBJECT
    if not obj.is_file():
        dest.unlink(missing_ok=True)
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    staged = dest.with_name(dest.name + ".new")
    shutil.copyfile(obj, staged)
    staged.chmod(0o644)
    staged.replace(dest)


def _install_release_dir(release_dir: Path) -> None:
    """pip-install a verified release as root. Review FR-001: the
    dependencies come only from the release's own requirements.lock --
    exact versions, each file checked against its sha256, wheels only --
    and the release itself is then built with the locked setuptools
    (--no-build-isolation) and nothing else (--no-deps), so pip resolves
    nothing unpinned from PyPI. The lock is inside the signed tarball, so
    the signature covers what gets installed. A release without a lock
    is refused rather than installed with whatever PyPI serves today."""
    lock = release_dir / LOCK_FILE
    if not lock.is_file():
        raise UpdateError(f"the release has no {LOCK_FILE}: refusing to install unpinned dependencies")
    pip = ["pip3", "install", "--break-system-packages", "--no-cache-dir"]
    _run([*pip, "--require-hashes", "--only-binary=:all:", "-r", str(lock)])
    _run([*pip, "--no-deps", "--no-build-isolation", "--", str(release_dir)])
    _install_xdp_object(release_dir, paths.XDP_BPF_OBJ_PATH)
    _stage_systemd_units(release_dir)
    _run(["systemctl", "daemon-reload"])


def _restart_services(services: tuple[str, ...]) -> None:
    for unit in services:
        if unit in _UNIT_FILES_NOT_RESTARTED:
            continue
        # try-restart (not restart): a no-op, successfully, for a unit
        # the admin never enabled -- e.g. fr-firewall isn't necessarily
        # running in a webUI-only test setup.
        _run(["systemctl", "try-restart", "--", validate.systemd_unit(unit)])


def _restart_webui_delayed(delay_seconds: int = _WEBUI_RESTART_DELAY_SECONDS) -> None:
    """Schedule fr-webui.service's restart a few seconds out via
    systemd-run, instead of restarting it synchronously here.

    fr-webui.service is the very process handling the HTTP request that
    triggered this update; killing it before this function returns would
    sever that connection before the browser ever saw a response. A
    short, decoupled delay lets the success page render first.
    """
    _run(
        [
            "systemd-run",
            "--quiet",
            f"--on-active={delay_seconds}",
            "--unit=fr-webui-restart",
            "systemctl",
            "try-restart",
            "--",
            WEBUI_SERVICE,
        ]
    )


def _installed_version() -> str:
    return __version__


def _install_and_activate(
    target_version: str,
    repo: str,
    releases_dir: Path,
    timeout: float,
    *,
    before_changes: Callable[[], None] = lambda: None,
) -> None:
    """Download + verify (changes nothing), then `before_changes()`, then
    install and restart -- the part that can leave the system half
    updated."""
    release_dir = _fetch_release(repo, target_version, releases_dir, timeout)
    before_changes()
    _install_release_dir(release_dir)
    _restart_services(SERVICES_TO_RESTART)
    _restart_webui_delayed()


def apply_update(
    target_version: str,
    *,
    repo: str = DEFAULT_REPO,
    state_path: Path = paths.UPDATE_STATE_PATH,
    releases_dir: Path = paths.RELEASES_DIR,
    timeout: float = 120.0,
) -> str:
    """Download, install and activate `target_version` from `repo`. Only a
    version newer than the installed one: an older one is refused before
    anything is downloaded (ROADMAP SEC-12) -- rollback_update() is the
    way back.

    Must run as root. Once the release is downloaded and verified --
    before `pip install` touches anything -- it records the running
    version as `previous_version` and the attempt as "in_progress", so
    `rollback_update` can undo it however far it got: a `pip install`
    that succeeded followed by a failed restart used to leave new code
    installed with no `previous_version`, and rollback refused (review
    triage C1). A failure before that point (download, verification)
    changed nothing and keeps the previous `previous_version`. On any
    failure the attempt and its error are recorded in `last_update` and
    re-raised as `UpdateError`.
    """
    target = parse_version(target_version)  # validate shape before touching anything
    current_version = _installed_version()
    # ROADMAP SEC-12 (review v0.2.0 R18): forward only. An older release
    # can be signed just as validly -- it was, when it came out -- and
    # installing it brings back whatever has been fixed since, so whoever
    # can get one installed (a stolen webUI session, a tampered mirror or
    # cache, a hand-typed CLI version) gets those holes back. The one way
    # back is rollback_update(), to the version this router itself
    # updated from. An installed version this can't parse fails closed.
    current = parse_version(current_version)
    if target == current:
        raise UpdateError(f"already running version {target_version}")
    if target < current:
        raise UpdateError(
            f"refusing to install {target_version}: it is older than the installed {current_version}, "
            "and an older release brings back what has been fixed since. To go back to the version "
            "this router updated from, roll back (webUI Update screen, or `firewall-cli update rollback`)."
        )
    state = load_state(current_version=current_version, path=state_path)

    changes_started = False

    def record_start() -> None:
        nonlocal changes_started
        state.previous_version = current_version
        state.last_update = {
            "action": "apply",
            "version": target_version,
            "applied_at": _now(),
            "status": "in_progress",
            "message": "",
        }
        save_state(state, state_path)
        changes_started = True

    try:
        _install_and_activate(target_version, repo, releases_dir, timeout, before_changes=record_start)
    except Exception as exc:
        hint = (f" -- the system may be partly updated; roll back to {current_version} "
                "(webUI Update screen, or `firewall-cli update rollback`)") if changes_started else ""
        state.last_update = {
            "action": "apply",
            "version": target_version,
            "applied_at": _now(),
            "status": "failed",
            "message": f"{exc}{hint}",
        }
        save_state(state, state_path)
        raise UpdateError(f"update to {target_version} failed: {exc}{hint}") from exc

    state.current_version = target_version
    state.last_update = {
        "action": "apply",
        "version": target_version,
        "applied_at": _now(),
        "status": "success",
        "message": "",
    }
    save_state(state, state_path)
    return target_version


def rollback_update(
    *,
    repo: str = DEFAULT_REPO,
    state_path: Path = paths.UPDATE_STATE_PATH,
    releases_dir: Path = paths.RELEASES_DIR,
    timeout: float = 120.0,
) -> str:
    """Reinstall the version recorded as `previous_version`.

    Only one level deep: a successful rollback clears `previous_version`,
    so rolling back a rollback is not supported (there is nothing left
    to roll back *to* that this module still knows about). Reuses the
    previous version's already-extracted source under `releases_dir`
    when present, so this can work even with no network access --
    useful exactly when the update being undone also broke connectivity.
    """
    current_version = _installed_version()
    state = load_state(current_version=current_version, path=state_path)
    if not state.previous_version:
        raise UpdateError("no previous version recorded to roll back to")
    target = state.previous_version
    # Security-lessons F1 / review triage C2: the state file names a
    # directory rmtree'd and pip-installed as root -- only a real version.
    parse_version(target)

    try:
        _install_and_activate(target, repo, releases_dir, timeout)
    except Exception as exc:
        state.last_update = {
            "action": "rollback",
            "version": target,
            "applied_at": _now(),
            "status": "failed",
            "message": str(exc),
        }
        save_state(state, state_path)
        raise UpdateError(f"rollback to {target} failed: {exc}") from exc

    state.current_version = target
    state.previous_version = None
    state.last_update = {
        "action": "rollback",
        "version": target,
        "applied_at": _now(),
        "status": "success",
        "message": "",
    }
    save_state(state, state_path)
    return target
