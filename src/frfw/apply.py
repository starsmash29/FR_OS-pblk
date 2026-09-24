"""Applying a generated nftables ruleset to the running kernel via `nft`.

Deliberately shells out to the `nft` binary rather than using a Python
nftables binding: it keeps the dependency footprint at "nftables package
installed" (true on any Debian firewall box) and makes `nft -c` syntax
checking trivial to reuse for both validation and apply.

Every real (non-dry-run) apply first snapshots the currently running
ruleset to a timestamped backup file, so a bad config can be rolled back
with `rollback_last()` / `firewall-cli rollback` without needing to
remember or re-derive the previous good state.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from frfw import paths


def _nft_env() -> dict[str, str]:
    """Environment for every ruleset load/list: TZ=UTC. `nft` converts
    `meta hour` values between the text it reads/prints and the kernel's
    UTC representation using its own process time zone; frfw writes
    scheduled rules in UTC already (frfw.nft.schedule), so nft must not
    shift them -- and a backup listed and later restored must round-trip
    through the same zone."""
    return {**os.environ, "TZ": "UTC"}


class NftError(Exception):
    """Raised when the `nft` binary rejects a ruleset or fails to apply it."""


@dataclass(frozen=True)
class ApplyResult:
    applied: bool
    message: str
    backup_path: Path | None = None


def check_syntax(ruleset: str) -> None:
    """Validate `ruleset` with `nft -c` without changing any kernel state.

    Raises `NftError` with nft's own stderr output if the syntax (or a
    reference to an undefined set/chain) is invalid.
    """
    _run_nft(["-c", "-f", "-"], ruleset)


def capture_running_ruleset() -> str:
    """Return the ruleset currently loaded in the kernel (`nft list ruleset`)."""
    try:
        proc = subprocess.run(
            ["nft", "list", "ruleset"], capture_output=True, text=True, env=_nft_env()
        )
    except FileNotFoundError as exc:
        raise NftError("'nft' binary not found; install the nftables package") from exc
    if proc.returncode != 0:
        raise NftError(proc.stderr.strip() or f"nft exited with status {proc.returncode}")
    return proc.stdout


def apply_ruleset(
    ruleset: str,
    *,
    dry_run: bool = False,
    backup_dir: Path = paths.BACKUP_DIR,
    backup_retention: int = paths.BACKUP_RETENTION,
) -> ApplyResult:
    """Validate and, unless `dry_run`, load `ruleset` into the kernel.

    Always syntax-checks first (`nft -c`) so a bad config never partially
    replaces the running ruleset. On a real apply, the ruleset that was
    running beforehand is backed up to `backup_dir` first.
    """
    check_syntax(ruleset)

    if dry_run:
        return ApplyResult(applied=False, message="Syntax OK (dry-run, not applied)")

    _require_root()

    backup_path = _backup_current_ruleset(backup_dir, backup_retention)
    _run_nft(["-f", "-"], ruleset)

    message = "Ruleset applied"
    if backup_path is not None:
        message += f" (previous ruleset backed up to {backup_path})"
    return ApplyResult(applied=True, message=message, backup_path=backup_path)


def list_backups(backup_dir: Path = paths.BACKUP_DIR) -> list[Path]:
    """Return known ruleset backups, oldest first."""
    if not backup_dir.is_dir():
        return []
    return sorted(backup_dir.glob("ruleset-*.nft"))


def rollback_last(backup_dir: Path = paths.BACKUP_DIR) -> Path:
    """Reload the most recent ruleset backup, returning the file used.

    Raises `NftError` if there is no backup to roll back to.
    """
    _require_root()
    backups = list_backups(backup_dir)
    if not backups:
        raise NftError(f"No ruleset backups found in {backup_dir}")
    latest = backups[-1]
    _run_nft(["-f", str(latest)], "")
    return latest


def _require_root() -> None:
    if os.geteuid() != 0:
        raise NftError(
            "This operation requires root privileges (got syntax-checked "
            "OK, but not loaded). Re-run as root, or use --dry-run."
        )


def _backup_current_ruleset(backup_dir: Path, retention: int) -> Path | None:
    current = capture_running_ruleset()
    if not current.strip():
        return None  # nothing loaded yet -- nothing worth backing up

    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"ruleset-{timestamp}.nft"
    # `nft list ruleset` output has no `flush ruleset` line, so loading it
    # back as-is would merge into whatever is currently running instead of
    # replacing it. Prepend flush to make rollback a true restore.
    backup_path.write_text(f"flush ruleset\n\n{current}")

    _prune_backups(backup_dir, retention)
    return backup_path


def _prune_backups(backup_dir: Path, retention: int) -> None:
    backups = sorted(backup_dir.glob("ruleset-*.nft"))
    for old in backups[: max(len(backups) - retention, 0)]:
        old.unlink(missing_ok=True)


def _run_nft(args: list[str], stdin_text: str) -> None:
    try:
        proc = subprocess.run(
            ["nft", *args],
            input=stdin_text,
            capture_output=True,
            text=True,
            env=_nft_env(),
        )
    except FileNotFoundError as exc:
        raise NftError("'nft' binary not found; install the nftables package") from exc

    if proc.returncode != 0:
        raise NftError(proc.stderr.strip() or f"nft exited with status {proc.returncode}")
