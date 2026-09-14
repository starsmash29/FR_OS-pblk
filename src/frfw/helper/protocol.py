"""Wire format for the apply-helper Unix socket protocol.

One JSON object per line, both directions. Deliberately tiny: the helper
exists so an unprivileged process (the future webUI) can ask a root-run
daemon to do exactly two things -- apply the canonical config, or roll
back to the previous ruleset -- without ever gaining a general command
execution or arbitrary-file-read/write capability.
"""

from __future__ import annotations

#: Commands the apply-helper understands. Notably absent: anything that
#: takes a caller-supplied file path -- the helper only ever touches
#: frfw.paths.CONFIG_PATH / BACKUP_DIR, configured when the daemon starts.
COMMANDS = ("ping", "apply", "rollback")

#: Maximum accepted request/response line length, to bound memory use from
#: a misbehaving or malicious local peer.
MAX_LINE_BYTES = 64 * 1024
