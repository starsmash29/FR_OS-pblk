"""Wire format for the update-helper Unix socket protocol.

Same one-JSON-object-per-line design as frfw.helper.protocol (the
firewall apply-helper's), and the same "deliberately tiny" philosophy --
but a separate module/daemon on purpose. That apply-helper's whole
design is "touches only CONFIG_PATH/BACKUP_DIR, no general command
execution" (see its own module docstring); installing packages,
rewriting systemd units and restarting services is a much broader
privilege surface, and bolting that onto the narrowly-scoped
apply-helper would widen ITS attack surface for functionality it has
nothing to do with. Two small, single-purpose daemons instead of one
bigger one with mixed responsibilities.
"""

from __future__ import annotations

#: Commands the update-helper understands. Notably absent: version
#: *checking* -- that needs no privilege at all (a read-only HTTPS GET),
#: so it is called directly, in-process, by whatever wants it (the
#: webUI, `firewall-cli update check`) instead of round-tripping through
#: a root daemon for no reason.
COMMANDS = ("ping", "apply", "rollback")

#: Maximum accepted request/response line length -- same bound as the
#: apply-helper's, for the same reason (see frfw.helper.protocol).
MAX_LINE_BYTES = 64 * 1024
