from __future__ import annotations

import time

import yaml
from fastapi.testclient import TestClient

import pytest

from frfw.config import parse_config
from frfw.webui.app import create_app
from frfw.webui.auth import AdminStore, SessionManager
from frfw.webui.auth_rate_limiter import BruteforceGuard


class FakeHelper:
    """An in-memory stand-in for the real Unix-socket apply-helper.

    Real save_config semantics (validate-then-write) without a running
    daemon or socket -- exactly what the real helper does, just in-process,
    so route tests exercise the same validation path production traffic
    would hit.

    authorize_ztna/ztna_status simulate the kernel's own timeout-based
    eviction with a plain dict + wall-clock deadline rather than talking
    to a real nftables set (this sandbox's test environment doesn't
    assume CAP_NET_ADMIN) -- frfw.ztna's own tests exercise the real
    `nft` behavior directly; this fake only needs to be faithful enough
    for route-level (redirect/flash-message/template) assertions.
    """

    def __init__(self, config_path):
        self.config_path = config_path
        self.applied = []
        self.rolled_back = False
        self._ztna_authorizations: dict[str, tuple[str, float]] = {}  # ip -> (username, expires_at)
        self.refresh_adblock_calls = 0
        self.refresh_adblock_result = {"ok": True, "message": "3 deduped domains written", "domain_count": 3}
        self.banned: list[tuple[str, int]] = []
        self.quarantined: dict[str, int] = {}  # ip -> expires_in, set by tests directly
        self.banned_ips: dict[str, int] = {}  # ip -> expires_in, set by tests directly
        self.ztna_sessions: dict[str, int] = {}  # ip -> expires_in, set by tests directly
        self.ram_modules: list[dict] = []  # [{"part_number": ..., "speed_mhz": ...}, ...]
        self.leases: list[dict] = []  # dhcp_leases() payload, set by tests directly
        self.iot_isolated: list[str] = []  # stands in for the kernel iot_isolated set
        self.iot_sync_calls: list[list[str]] = []

    def ping(self):
        return {"ok": True, "message": "pong"}

    def save_config(self, yaml_text: str) -> dict:
        try:
            parse_config(yaml.safe_load(yaml_text))
        except Exception as exc:  # noqa: BLE001 -- mirrors the real helper's catch-all
            return {"ok": False, "message": str(exc)}
        self.config_path.write_text(yaml_text)
        return {"ok": True, "message": f"Config saved to {self.config_path}"}

    def apply(self, dry_run: bool = False) -> dict:
        self.applied.append(dry_run)
        return {"ok": True, "message": "dry-run ok" if dry_run else "applied"}

    def rollback(self) -> dict:
        self.rolled_back = True
        return {"ok": True, "message": "rolled back"}

    def authorize_ztna(self, ip: str, username: str) -> dict:
        if not self.config_path.is_file():
            return {"ok": False, "message": f"Config file not found: {self.config_path}"}
        try:
            config = parse_config(yaml.safe_load(self.config_path.read_text()))
        except Exception as exc:  # noqa: BLE001 -- mirrors the real helper's catch-all
            return {"ok": False, "message": str(exc)}
        if not config.ztna.enabled:
            return {"ok": False, "message": "ZTNA gate is disabled in the current config"}
        if not any(u.username == username for u in config.ztna.users):
            return {"ok": False, "message": f"no such ZTNA user {username!r}"}
        ttl = config.ztna.session_ttl_seconds
        self._ztna_authorizations[ip] = (username, time.time() + ttl)
        return {"ok": True, "message": f"{ip} authorized", "expires_in": ttl}

    def ztna_status(self, ip: str) -> dict:
        entry = self._ztna_authorizations.get(ip)
        if entry is None:
            return {"ok": True, "authorized": False}
        username, expires_at = entry
        remaining = int(expires_at - time.time())
        if remaining <= 0:
            del self._ztna_authorizations[ip]
            return {"ok": True, "authorized": False}
        return {"ok": True, "authorized": True, "username": username, "expires_in": remaining}

    def refresh_adblock(self) -> dict:
        self.refresh_adblock_calls += 1
        return self.refresh_adblock_result

    def ban_ip(self, ip: str, duration_seconds: int = 3600) -> dict:
        self.banned.append((ip, duration_seconds))
        return {"ok": True, "message": f"{ip} jailed for {duration_seconds}s"}

    def ids_quarantine_status(self) -> dict:
        quarantined = [{"ip": ip, "expires_in": exp} for ip, exp in self.quarantined.items()]
        return {"ok": True, "quarantined": quarantined, "count": len(quarantined)}

    def bruteforce_status(self) -> dict:
        banned = [{"ip": ip, "expires_in": exp} for ip, exp in self.banned_ips.items()]
        return {"ok": True, "banned": banned, "count": len(banned)}

    def ztna_sessions_status(self) -> dict:
        sessions = [{"ip": ip, "expires_in": exp} for ip, exp in self.ztna_sessions.items()]
        return {"ok": True, "sessions": sessions, "count": len(sessions)}

    def hw_ram_info(self) -> dict:
        return {"ok": True, "modules": self.ram_modules}

    def dhcp_leases(self) -> dict:
        return {"ok": True, "leases": self.leases, "count": len(self.leases)}

    def iot_sync_isolation(self, macs: list[str]) -> dict:
        """Mirrors the real helper's checks: refuses while iot is disabled
        in the saved config, and never isolates a trusted MAC."""
        self.iot_sync_calls.append(list(macs))
        config = parse_config(yaml.safe_load(self.config_path.read_text()))
        if not config.iot.enabled:
            return {"ok": False, "message": "IoT isolation is disabled in the current config"}
        trusted = set(config.iot.trusted_macs)
        self.iot_isolated = [m.lower() for m in macs if m.lower() not in trusted]
        return {"ok": True, "isolated": list(self.iot_isolated), "count": len(self.iot_isolated)}

    def iot_isolation_status(self) -> dict:
        return {"ok": True, "isolated": list(self.iot_isolated), "count": len(self.iot_isolated)}


class FakeUpdateHelper:
    """An in-memory stand-in for the real Unix-socket update-helper.

    Never touches frfw.update's real apply/rollback logic (that has its
    own tests in test_update.py / test_update_helper.py) -- this just
    records what the route asked for, so route tests can assert on the
    HTTP-level behavior (redirects, flash messages) without a running
    update-helper daemon.
    """

    def __init__(self) -> None:
        self.applied = []
        self.rolled_back = 0
        self.apply_result = {"ok": True, "message": "Updated to 0.2.0"}
        self.rollback_result = {"ok": True, "message": "Rolled back to 0.1.0"}

    def ping(self) -> dict:
        return {"ok": True, "message": "pong"}

    def apply(self, version: str) -> dict:
        self.applied.append(version)
        return self.apply_result

    def rollback(self) -> dict:
        self.rolled_back += 1
        return self.rollback_result


@pytest.fixture
def webui_env(tmp_path):
    config_path = tmp_path / "config.yaml"
    return {
        "config_path": config_path,
        "admin_store": AdminStore(tmp_path / "auth.json"),
        "session_manager": SessionManager(tmp_path / "secret.key"),
        "helper": FakeHelper(config_path),
        "update_helper": FakeUpdateHelper(),
        "ai_ids_state_path": tmp_path / "ai_ids_state.json",
        "update_state_path": tmp_path / "update_state.json",
        "xdp_state_path": tmp_path / "xdp_state.json",
        "adblock_hosts_path": tmp_path / "adblock.hosts",
        "adblock_category_dir": tmp_path / "adblock.d",
        "bruteforce_guard": BruteforceGuard(),
        "iot_inventory_path": tmp_path / "iot_inventory.json",
        "appid_usage_path": tmp_path / "appid_usage.json",
        "audit_log_path": tmp_path / "audit.log",
        # No real multicast/ARP/IEEE registry in route tests: an empty
        # ARP table, an empty OUI file and a canned mDNS answer.
        "iot_scan_options": _iot_scan_options(tmp_path),
    }


def _iot_scan_options(tmp_path):
    arp = tmp_path / "arp"
    arp.write_text("IP address HW type Flags HW address Mask Device\n")
    oui = tmp_path / "oui.csv"
    oui.write_text(
        "Registry,Assignment,Organization Name,Organization Address\nMA-L,240AC4,Espressif Inc.,x\n"
    )
    return {
        "arp_path": arp,
        "oui_path": oui,
        "mdns_fn": lambda addrs: {"10.0.1.50": {"_esphomelib._tcp"}},
    }


@pytest.fixture
def app(webui_env):
    return create_app(**webui_env)


@pytest.fixture
def client(app):
    return TestClient(app, follow_redirects=False)


@pytest.fixture
def logged_in_client(client, webui_env):
    webui_env["admin_store"].set_password("admin", "hunter22")
    response = client.post("/login", data={"username": "admin", "password": "hunter22"})
    assert response.status_code == 303
    return client
