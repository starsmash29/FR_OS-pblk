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
"installing" it means downloading that tag's source tarball
(`https://github.com/<repo>/archive/refs/tags/<tag>.tar.gz`) and
`pip install`ing it in place, exactly like a fresh install would.

**Known limitation, stated plainly**: there is no cryptographic
signature verification of the downloaded release -- HTTPS-to-GitHub is
the only trust boundary right now, the same as `git clone` or `pip
install` from an unpinned index would give you. Signing releases (e.g.
with `cosign` or a GPG-signed checksum file) is a reasonable follow-up
once there are real, tagged releases to sign.

Rollback is a single level deep: applying an update remembers the
version you were on as `previous_version`; rolling back reinstalls that
version and clears it, so rolling back a rollback is not supported. If a
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

from frfw import __version__, paths

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
    "fr-apply-helper.service",
    "fr-firewall.service",
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

_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


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
    match = _VERSION_RE.match(text.strip())
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


def _release_from_json(raw: dict) -> ReleaseInfo:
    tag = str(raw.get("tag_name") or "")
    return ReleaseInfo(
        tag=tag,
        version=tag[1:] if tag.startswith("v") else tag,
        notes=str(raw.get("body") or ""),
        published_at=raw.get("published_at"),
        html_url=str(raw.get("html_url") or ""),
    )


def list_releases(
    repo: str = DEFAULT_REPO, limit: int = 10, timeout: float = 10.0
) -> list[ReleaseInfo]:
    """Most recent releases (newest first), for a changelog display."""
    try:
        raw = _fetch_json(
            f"https://api.github.com/repos/{repo}/releases?per_page={limit}", timeout
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
        raw = _fetch_json(f"https://api.github.com/repos/{repo}/releases/latest", timeout)
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


def _download_tarball(repo: str, tag: str, dest: Path, timeout: float) -> None:
    url = f"https://github.com/{repo}/archive/refs/tags/{tag}.tar.gz"
    request = urllib.request.Request(url, headers={"User-Agent": "fr_os-update"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            with dest.open("wb") as f:
                shutil.copyfileobj(response, f)
    except urllib.error.URLError as exc:
        raise UpdateError(f"could not download {url}: {exc}") from exc


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
        members = tar.getmembers()
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


def _fetch_release(repo: str, version: str, releases_dir: Path, timeout: float) -> Path:
    """Return a local directory containing `version`'s source, downloading
    and extracting it if not already cached under `releases_dir`."""
    existing = releases_dir / version
    if (existing / "pyproject.toml").is_file():
        return existing

    releases_dir.mkdir(parents=True, exist_ok=True)
    tag = version if version.startswith("v") else f"v{version}"
    with tempfile.TemporaryDirectory(dir=releases_dir) as tmp:
        tmp_path = Path(tmp)
        tarball = tmp_path / "release.tar.gz"
        _download_tarball(repo, tag, tarball, timeout)
        extracted_root = _safe_extract(tarball, tmp_path / "extracted")

        if existing.exists():
            shutil.rmtree(existing)
        shutil.move(str(extracted_root), str(existing))

    return existing


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


def _install_release_dir(release_dir: Path) -> None:
    _run(
        [
            "pip3",
            "install",
            "--break-system-packages",
            "--no-cache-dir",
            f"{release_dir}[webui]",
        ]
    )
    _stage_systemd_units(release_dir)
    _run(["systemctl", "daemon-reload"])


def _restart_services(services: tuple[str, ...]) -> None:
    for unit in services:
        if unit in _UNIT_FILES_NOT_RESTARTED:
            continue
        # try-restart (not restart): a no-op, successfully, for a unit
        # the admin never enabled -- e.g. fr-firewall isn't necessarily
        # running in a webUI-only test setup.
        _run(["systemctl", "try-restart", unit])


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
            WEBUI_SERVICE,
        ]
    )


def _installed_version() -> str:
    return __version__


def _install_and_activate(
    target_version: str, repo: str, releases_dir: Path, timeout: float
) -> None:
    release_dir = _fetch_release(repo, target_version, releases_dir, timeout)
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
    """Download, install and activate `target_version` from `repo`.

    Must run as root. Records the currently-installed version as
    `previous_version` *before* switching, so `rollback_update` can undo
    a bad update. On any failure, the attempt (and its error message) is
    recorded in the state file's `last_update` and re-raised as
    `UpdateError` -- the caller (the update-helper daemon, or the CLI)
    decides how to surface that; this function never leaves a partial
    failure silent.
    """
    parse_version(target_version)  # validate shape before touching anything
    current_version = _installed_version()
    state = load_state(current_version=current_version, path=state_path)

    if target_version == current_version:
        raise UpdateError(f"already running version {target_version}")

    try:
        _install_and_activate(target_version, repo, releases_dir, timeout)
    except Exception as exc:
        state.last_update = {
            "action": "apply",
            "version": target_version,
            "applied_at": _now(),
            "status": "failed",
            "message": str(exc),
        }
        save_state(state, state_path)
        raise UpdateError(f"update to {target_version} failed: {exc}") from exc

    state.previous_version = current_version
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
