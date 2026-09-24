"""FastAPI app factory for the frfw webUI.

Everything the routes need (config path, admin store, session manager,
apply-helper client, AI IDS state path) lives on `app.state`, set here --
see frfw.webui.deps for how routes pull it back out. This is what lets
tests build an isolated app pointed at a tmp_path config with a fake
helper, instead of depending on the real /etc/fr_os and a running
apply-helper daemon.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI

from frfw import paths
from frfw.webui.auth import AdminStore, SessionManager
from frfw.webui.auth_rate_limiter import BruteforceGuard
from frfw.webui.helper_client import (
    HelperClient,
    SocketHelperClient,
    SocketUpdateHelperClient,
    UpdateHelperClient,
)
from frfw.webui.routes import (
    adblock,
    ai_ids,
    auth,
    dashboard,
    dhcp,
    interfaces,
    iot,
    metrics,
    nat,
    rules,
    system,
    update,
    xdp,
    ztna,
)


def create_app(
    *,
    config_path: Path = paths.CONFIG_PATH,
    admin_store: AdminStore | None = None,
    session_manager: SessionManager | None = None,
    helper: HelperClient | None = None,
    update_helper: UpdateHelperClient | None = None,
    ai_ids_state_path: Path = paths.AI_IDS_STATE_PATH,
    update_state_path: Path = paths.UPDATE_STATE_PATH,
    xdp_state_path: Path = paths.XDP_STATE_PATH,
    adblock_hosts_path: Path = paths.ADBLOCK_HOSTS_PATH,
    bruteforce_guard: BruteforceGuard | None = None,
    iot_inventory_path: Path = paths.IOT_INVENTORY_PATH,
    iot_scan_options: dict | None = None,
) -> FastAPI:
    app = FastAPI(title="FR_OS webUI")
    app.state.config_path = config_path
    app.state.admin_store = admin_store or AdminStore()
    app.state.session_manager = session_manager or SessionManager()
    app.state.helper = helper or SocketHelperClient()
    app.state.update_helper = update_helper or SocketUpdateHelperClient()
    app.state.ai_ids_state_path = ai_ids_state_path
    app.state.update_state_path = update_state_path
    app.state.xdp_state_path = xdp_state_path
    app.state.adblock_hosts_path = adblock_hosts_path
    app.state.bruteforce_guard = bruteforce_guard or BruteforceGuard()
    app.state.iot_inventory_path = iot_inventory_path
    # Extra keyword arguments for frfw.iot.scanner.run_scan (mdns_fn,
    # arp_path, oui_path) -- empty in production, overridden by tests.
    app.state.iot_scan_options = iot_scan_options or {}

    app.include_router(auth.router)
    app.include_router(dashboard.router)
    app.include_router(interfaces.router)
    app.include_router(rules.router)
    app.include_router(nat.router)
    app.include_router(dhcp.router)
    app.include_router(ai_ids.router)
    app.include_router(update.router)
    app.include_router(xdp.router)
    app.include_router(ztna.router)
    app.include_router(system.router)
    app.include_router(adblock.router)
    app.include_router(iot.router)
    app.include_router(metrics.router)

    return app
