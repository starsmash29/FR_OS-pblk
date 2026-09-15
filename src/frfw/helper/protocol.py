"""Wire format for the apply-helper Unix socket protocol.

One JSON object per line, both directions. Deliberately narrow: the
helper exists so an unprivileged process (the webUI) can ask a root-run
daemon to perform specific, individually-named privileged operations
-- applying the canonical config, rolling back, writing a new config
after validating it, or touching the ZTNA gate's kernel state -- without
ever gaining a general command execution or arbitrary-file-read/write
capability. See `COMMANDS` for exactly what that set is today.
"""

from __future__ import annotations

#: Commands the apply-helper understands. Notably absent: anything that
#: takes a caller-supplied file path -- the helper only ever touches
#: frfw.paths.CONFIG_PATH / BACKUP_DIR, configured when the daemon starts.
#: "authorize_ztna"/"ztna_status" are the ZTNA gate's two commands
#: (see frfw.ztna): both require root (even the read-only status check
#: -- reading nftables state needs CAP_NET_ADMIN, confirmed directly),
#: so both must go through this socket rather than the unprivileged
#: webUI process touching `nft` itself.
#: "refresh_adblock" (see frfw.adblock) downloads and writes the deduped
#: hosts-format blocklist -- the download itself needs no privilege, but
#: the final write lands under /etc/fr_os and the webUI must never write
#: there directly, so the whole operation goes through this socket
#: rather than splitting "fetch here, write there" across a privilege
#: boundary mid-operation.
#: "ban_ip" (see frfw.bruteforce) adds a source IP to the kernel-space
#: brute-force jail set -- the webUI's in-memory failed-login counter
#: (frfw.webui.auth_rate_limiter) decides *when* to call this, but
#: touching nftables itself needs the same CAP_NET_ADMIN as the ZTNA
#: commands above, so the actual ban always goes through here.
COMMANDS = (
    "ping",
    "apply",
    "rollback",
    "save_config",
    "authorize_ztna",
    "ztna_status",
    "refresh_adblock",
    "ban_ip",
)

#: Maximum accepted request/response line length, to bound memory use from
#: a misbehaving or malicious local peer.
MAX_LINE_BYTES = 64 * 1024
