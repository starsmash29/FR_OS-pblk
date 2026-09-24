"""Follow a systemd unit's journal output line by line.

Shared by the unprivileged background daemons (fr-ai-ids, fr-appid) that
read another unit's log: `journalctl -f -o cat` needs nothing beyond
membership of the systemd-journal group (SupplementaryGroups= in their
units), the same mechanism the webUI's live XDP log stream uses.
"""

from __future__ import annotations

import subprocess
import sys
import time
from typing import Callable

#: Restart backoff when the followed unit isn't running yet or the pipe
#: closes -- retried forever, so a hiccup in one log source never takes
#: the whole daemon down.
JOURNAL_RETRY_SECONDS = 5.0


def tail_journal_forever(
    unit: str, handler: Callable[[str], None], *, program: str
) -> None:  # pragma: no cover -- a blocking subprocess loop
    """Hand every new line `unit` logs (from now on, no backlog) to
    `handler`. Returns only if journalctl itself is missing."""
    while True:
        try:
            proc = subprocess.Popen(
                ["journalctl", "-u", unit, "-f", "-n", "0", "-o", "cat"],
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
