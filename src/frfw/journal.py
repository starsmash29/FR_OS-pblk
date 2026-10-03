"""Follow another unit's log file line by line.

Shared by the unprivileged background daemons (fr-ai-ids, fr-appid),
which read the XDP SNI events (paths.SNI_EVENTS_PATH) and the resolver's
query log (paths.DNS_QUERY_LOG_PATH) from files their writers keep for
them. Reading one takes membership of that file's group -- not the
systemd-journal group, which reads every unit's log and the kernel's
(ROADMAP SEC-4, review v0.2.0 R10). The module keeps its name from when
it followed journals.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Callable


#: Restart backoff when the followed unit isn't running yet or the pipe
#: closes -- retried forever, so a hiccup in one log source never takes
#: the whole daemon down.
FOLLOW_RETRY_SECONDS = 5.0


def follow_file_forever(
    path: Path, handler: Callable[[str], None], *, program: str
) -> None:  # pragma: no cover -- a blocking loop, see tests/test_sni_event_file.py
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
        time.sleep(FOLLOW_RETRY_SECONDS)
