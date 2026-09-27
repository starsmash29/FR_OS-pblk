"""The privileged helpers' Unix-socket protocol.

Only the client side is re-exported here. The server
(`frfw.helper.server.ApplyHelperServer`) is imported from its module:
importing it from this package made every client -- the network-parsing
daemons included -- pull in frfw.provision, which imports those daemons
back (a circular import that broke `import frfw.provision` on its own).
"""

from frfw.helper.client import (
    HelperError,
    apply_config,
    ping,
    rollback,
    save_config,
    send_command,
)

__all__ = [
    "HelperError",
    "apply_config",
    "ping",
    "rollback",
    "save_config",
    "send_command",
]
