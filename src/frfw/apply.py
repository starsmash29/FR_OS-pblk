"""Applying a generated nftables ruleset to the running kernel via `nft`.

Deliberately shells out to the `nft` binary rather than using a Python
nftables binding: it keeps the dependency footprint at "nftables package
installed" (true on any Debian firewall box) and makes `nft -c` syntax
checking trivial to reuse for both validation and apply.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass


class NftError(Exception):
    """Raised when the `nft` binary rejects a ruleset or fails to apply it."""


@dataclass(frozen=True)
class ApplyResult:
    applied: bool
    message: str


def check_syntax(ruleset: str) -> None:
    """Validate `ruleset` with `nft -c` without changing any kernel state.

    Raises `NftError` with nft's own stderr output if the syntax (or a
    reference to an undefined set/chain) is invalid.
    """
    _run_nft(["-c", "-f", "-"], ruleset)


def apply_ruleset(ruleset: str, *, dry_run: bool = False) -> ApplyResult:
    """Validate and, unless `dry_run`, load `ruleset` into the kernel.

    Always syntax-checks first (`nft -c`) so a bad config never partially
    replaces the running ruleset.
    """
    check_syntax(ruleset)

    if dry_run:
        return ApplyResult(applied=False, message="Syntax OK (dry-run, not applied)")

    if os.geteuid() != 0:
        raise NftError(
            "Applying a ruleset requires root privileges (got syntax-checked "
            "OK, but not loaded). Re-run as root, or use --dry-run."
        )

    _run_nft(["-f", "-"], ruleset)
    return ApplyResult(applied=True, message="Ruleset applied")


def _run_nft(args: list[str], stdin_text: str) -> None:
    try:
        proc = subprocess.run(
            ["nft", *args],
            input=stdin_text,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise NftError(
            "'nft' binary not found; install the nftables package"
        ) from exc

    if proc.returncode != 0:
        raise NftError(proc.stderr.strip() or f"nft exited with status {proc.returncode}")
