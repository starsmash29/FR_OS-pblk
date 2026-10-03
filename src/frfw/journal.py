"""Follow another unit's output line by line.

Shared by the unprivileged background daemons (fr-ai-ids, fr-appid):

- `follow_file_forever` follows a log file another unit writes for its
  readers -- the XDP SNI events (paths.SNI_EVENTS_PATH). Reading it takes
  only membership of that file's group, not the whole journal (ROADMAP
  SEC-4, review v0.2.0 R10).
- `tail_journal_forever` follows a unit's journal. `journalctl -f -o
  cat` needs membership of the systemd-journal group, which can read
  every unit's log; it remains only for the resolver's query log until
  that has a file of its own too.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

from frfw import validate

#: Restart backoff when the followed unit isn't running yet or the pipe
#: closes -- retried forever, so a hiccup in one log source never takes
#: the whole daemon down.
JOURNAL_RETRY_SECONDS = 5.0


def follow_file_forever(
    path: Path, handler: Callable[[str], None], *, program: str
) -> None:  # pragma: no cover -- a blocking subprocess loop, see tests/test_journal_follow.py
    """Hand every line appended to `path` from now on to `handler`.

    `tail -F` does the following: it waits for a file that doesn't exist
    yet, and starts over when the writer empties it (frfw.xdp.EventFile)
    or it is replaced. Returns only if tail itself is missing."""
    while True:
        try:
            proc = subprocess.Popen(
                ["tail", "-n", "0", "-F", "--", str(path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                handler(line.strip())
        except FileNotFoundError:
            print(f"{program}: 'tail' not found; {path} signal disabled", file=sys.stderr)
            return
        time.sleep(JOURNAL_RETRY_SECONDS)


def tail_journal_forever(
    unit: str, handler: Callable[[str], None], *, program: str
) -> None:  # pragma: no cover -- a blocking subprocess loop
    """Hand every new line `unit` logs (from now on, no backlog) to
    `handler`. Returns only if journalctl itself is missing."""
    while True:
        try:
            proc = subprocess.Popen(
                ["journalctl", "-u", validate.systemd_unit(unit), "-f", "-n", "0", "-o", "cat"],
                stdout=subprocess.PIPE,
                text=True,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                handler(line.strip())
        except FileNotFoundError:
            print(f"{program}: 'journalctl' not found; {unit} signal disabled", file=sys.stderr)
            return
        time.sleep(JOURNAL_RETRY_SECONDS)
