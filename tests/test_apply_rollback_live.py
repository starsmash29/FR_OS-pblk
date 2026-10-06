"""A failed apply puts the router back as it was, on a real kernel (ROADMAP SEC-5).

Review v0.2.0 R6: an apply stopped at the first failing step and left
the steps before it applied. Here every step runs for real -- nft, `ip`,
the files -- in a network namespace of its own, through
`frfw.provision.apply_all` and `firewall-cli apply`, and only the one
thing that can't run in a test, the service manager restarting Kea, is
made to fail (`kea._restart_kea_service`): the moment a real router's DHCP
server refuses to start.

- With a config applied in full before (config A, recorded), config B
  fails at its DHCP step: the ruleset is A's again, with the ban added
  in between still in it and its time running; the LAN address B added
  is gone and A's is there; the Kea config B wrote is gone; the record
  still says A.
- Without a record, the ruleset that was loaded is put back as it was
  read, its ban included.
- At boot (`apply --fail-closed`), the router comes up with A when B
  fails, says so, and raises a security alert.
- A config the preflight refuses changes nothing at all.
- An apply held for confirmation (ROADMAP SEC-26) that is reverted, or
  still pending at boot, leaves the router on A: A's ruleset and LAN
  address, config.yaml A again, the unconfirmed config kept.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import uuid

import pytest
import yaml

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0 or not all(shutil.which(t) for t in ("ip", "nft", "kea-dhcp4")),
    reason="needs root, iproute2, nft and kea-dhcp4",
)

#: Runs in the namespace: every path FR_OS writes is under the test's
#: tmp directory, sshd is out of the picture (tests/conftest.py does the
#: same), and Kea's service restart fails when asked to.
_DRIVER = textwrap.dedent(
    """
    import json, sys
    from pathlib import Path
    tmp = Path(sys.argv[1]); job = json.loads(sys.argv[2])
    from frfw import kea, management, paths, wireguard
    for name, rel in {"APPLIED_CONFIG_PATH": "applied-config.yaml", "BACKUP_DIR": "backups",
                      "SCHEDULE_STATE_PATH": "schedule.json", "XDP_STATE_PATH": "xdp.json",
                      "PQC_OPENSSL_CONF_PATH": "pqc.cnf", "SSHD_PQC_DROPIN_PATH": "kex.conf",
                      "SSHD_MANAGEMENT_DROPIN_PATH": "mgmt.conf", "ADBLOCK_HOSTS_PATH": "adblock.hosts",
                      "ADBLOCK_DNSMASQ_CONF_PATH": "dnsmasq.conf", "ADBLOCK_CATEGORY_DIR": "adblock.d",
                      "SENSOR_CONFIG_PATH": "sensor-config.yaml", "AUDIT_LOG_DIR": "log",
                      "AUDIT_LOG_PATH": "log/audit.log", "WIREGUARD_KEY_PATH": "wg/private.key",
                      "APPLY_PENDING_PATH": "apply-pending.json", "APPLY_LOCK_PATH": ".apply.lock",
                      "REJECTED_CONFIG_PATH": "config.rejected.yaml"}.items():
        setattr(paths, name, tmp / rel)
    from frfw import apply_confirm
    apply_confirm._start_waiting = lambda: None  # the host's systemd is not this router's
    kea.KEA_CONFIG_PATH = tmp / "kea-dhcp4.conf"
    management.SSHD_BINARY = "fr-os-tests-have-no-sshd"

    def refuses():
        raise kea.KeaError("Job for kea-dhcp4-server.service failed")
    kea._restart_kea_service = refuses

    from frfw import bruteforce, cli, provision
    from frfw.config import read_config
    from frfw.transaction import ApplyError
    out = {}
    if job["do"] == "apply":
        config, text = read_config(job["config"])
        try:
            provision.apply_all(config, backup_dir=paths.BACKUP_DIR, kea_config_path=kea.KEA_CONFIG_PATH,
                                schedule_state_path=paths.SCHEDULE_STATE_PATH, xdp_state_path=paths.XDP_STATE_PATH,
                                pqc_conf_path=paths.PQC_OPENSSL_CONF_PATH, ssh_kex_dropin_path=paths.SSHD_PQC_DROPIN_PATH,
                                adblock_hosts_path=paths.ADBLOCK_HOSTS_PATH,
                                adblock_dnsmasq_conf_path=paths.ADBLOCK_DNSMASQ_CONF_PATH,
                                adblock_category_dir=paths.ADBLOCK_CATEGORY_DIR,
                                ssh_management_dropin_path=paths.SSHD_MANAGEMENT_DROPIN_PATH,
                                source_text=text if job.get("record", True) else None)
            out["ok"] = True
        except ApplyError as exc:
            out.update(ok=False, error=str(exc), changed=exc.changed, step=exc.step,
                       rolled_back=list(exc.rolled_back), not_rolled_back=list(exc.not_rolled_back))
    elif job["do"] == "ban":
        bruteforce.ban_ip(job["ip"], 600)
    elif job["do"] == "boot":
        out["code"] = cli.main(["apply", "--fail-closed", job["config"]])
    elif job["do"] == "cli":
        out["code"] = cli.main(job["argv"])
    print(json.dumps(out))
    """
)


def _sh(*args, ns=None, check=True, input=None):
    cmd = (["ip", "netns", "exec", ns] if ns else []) + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=check, input=input)


def _config(lan_address: str, *, rule: str, dhcp: bool = False) -> dict:
    raw = {
        "version": 1, "hostname": "router",
        "zones": {"lan": {}, "wan": {}},
        "interfaces": {"lan": {"device": "lan0", "zone": "lan", "address": lan_address},
                       "wan": {"device": "wan0", "zone": "wan", "address": "192.0.2.2/24"}},
        "rules": [{"name": rule, "action": "accept", "from_zone": "lan", "to_zone": "wan"}],
        "nat": {"masquerade": [{"out_zone": "wan"}]},
    }
    if dhcp:
        raw["dhcp"] = {"lan": {"range_start": "10.88.2.100", "range_end": "10.88.2.200", "dns_servers": ["10.88.2.1"]}}
    return raw


@pytest.fixture
def router(tmp_path):
    """A namespace with a LAN and a WAN device; `run` drives FR_OS in it."""
    ns = f"fr5{uuid.uuid4().hex[:6]}"
    _sh("ip", "netns", "add", ns)
    try:
        _sh("ip", "link", "set", "lo", "up", ns=ns)
        for device in ("lan0", "wan0"):  # veth: this kernel may have no dummy driver
            _sh("ip", "link", "add", device, "type", "veth", "peer", "name", f"{device}p", ns=ns)
        (tmp_path / "driver.py").write_text(_DRIVER)
        configs = {"A": _config("10.88.1.1/24", rule="lan-out-a"),
                   "B": _config("10.88.2.1/24", rule="lan-out-b", dhcp=True),
                   "C": _config("10.88.3.1/24", rule="lan-out-c")}
        for name, raw in configs.items():
            (tmp_path / f"{name}.yaml").write_text(yaml.safe_dump(raw))

        def run(**job):
            if "config" in job:
                job["config"] = str(tmp_path / f"{job['config']}.yaml")
            proc = _sh(sys.executable, str(tmp_path / "driver.py"), str(tmp_path), json.dumps(job),
                       ns=ns, check=False)
            assert proc.returncode == 0, proc.stderr
            return json.loads(proc.stdout.strip().splitlines()[-1]), proc.stderr

        def addresses(device):
            out = _sh("ip", "-j", "addr", "show", "dev", device, ns=ns).stdout
            return sorted(f"{a['local']}/{a['prefixlen']}" for a in json.loads(out)[0]["addr_info"]
                          if a["family"] == "inet")

        def ruleset():
            return _sh("nft", "list", "ruleset", ns=ns).stdout

        yield {"run": run, "addresses": addresses, "ruleset": ruleset, "tmp": tmp_path, "ns": ns}
    finally:
        _sh("ip", "netns", "del", ns, check=False)


def _without_expiry(ruleset: str) -> str:
    """The ruleset with set elements' times left out: a rebuilt set carries
    each element with the time it had left as its timeout (review FR-002),
    checked separately (`_ban_left`)."""
    return re.sub(r"(\d+\.\d+\.\d+\.\d+) timeout \S+( expires \S+)?", r"\1", ruleset)


def _ban_left(ruleset: str, ip: str) -> int | None:
    found = re.search(rf"{re.escape(ip)} timeout \S+ expires (?:(\d+)m)?(?:(\d+)s)?", ruleset)
    return None if not found else int(found.group(1) or 0) * 60 + int(found.group(2) or 0)


def test_a_failed_apply_puts_back_the_last_applied_config(router):
    run, tmp = router["run"], router["tmp"]
    assert run(do="apply", config="A")[0] == {"ok": True}
    assert (tmp / "applied-config.yaml").read_text() == (tmp / "A.yaml").read_text()
    assert oct((tmp / "applied-config.yaml").stat().st_mode & 0o777) == "0o600"
    run(do="ban", ip="203.0.113.7")
    before = router["ruleset"]()
    assert "lan-out-a" in before and _ban_left(before, "203.0.113.7")

    result, _ = run(do="apply", config="B")
    assert result["ok"] is False and result["changed"] is True
    assert result["step"] == "DHCP (Kea)" and "kea-dhcp4-server" in result["error"]
    # Undone last-first: the firewall is the last thing put back.
    assert result["rolled_back"][-1] == "the firewall"
    assert {"DHCP (Kea)", "interface addresses"} <= set(result["rolled_back"])
    assert result["not_rolled_back"] == []

    after = router["ruleset"]()
    assert _without_expiry(after) == _without_expiry(before), "the ruleset is not A's again"
    assert "lan-out-b" not in after
    assert 500 < _ban_left(after, "203.0.113.7") <= 600, "the ban made after A was lost"
    assert router["addresses"]("lan0") == ["10.88.1.1/24"], "B's LAN address stayed"
    assert not (tmp / "kea-dhcp4.conf").exists(), "B's Kea config stayed"
    assert (tmp / "applied-config.yaml").read_text() == (tmp / "A.yaml").read_text()


def test_without_a_record_the_ruleset_read_before_is_put_back(router):
    run = router["run"]
    assert run(do="apply", config="A", record=False)[0] == {"ok": True}
    assert not (router["tmp"] / "applied-config.yaml").exists()
    run(do="ban", ip="203.0.113.8")
    before = router["ruleset"]()

    result, _ = run(do="apply", config="B", record=False)
    assert result["ok"] is False and "the firewall" in result["rolled_back"]
    after = router["ruleset"]()
    assert _without_expiry(after) == _without_expiry(before)
    assert 500 < _ban_left(after, "203.0.113.8") <= 600
    assert router["addresses"]("lan0") == ["10.88.1.1/24"]


def test_at_boot_a_failing_config_falls_back_to_the_last_applied_one(router):
    run, tmp = router["run"], router["tmp"]
    assert run(do="apply", config="A")[0] == {"ok": True}
    result, stderr = run(do="boot", config="B")
    assert result["code"] == 0
    assert "config.yaml could not be applied" in stderr
    ruleset = router["ruleset"]()
    assert "lan-out-a" in ruleset and "lan-out-b" not in ruleset
    assert router["addresses"]("lan0") == ["10.88.1.1/24"]
    alerts = [json.loads(line) for line in (tmp / "log" / "audit.log").read_text().splitlines()]
    assert any("runs the last config that was applied in full" in a.get("alert", "") for a in alerts)


def test_a_config_the_preflight_refuses_changes_nothing(router):
    run, tmp = router["run"], router["tmp"]
    assert run(do="apply", config="A")[0] == {"ok": True}
    before = router["ruleset"]()
    bad = _config("10.88.3.1/24", rule="lan-out-c")
    bad["interfaces"]["lan"]["device"] = "lan9"  # not on this machine
    (tmp / "C.yaml").write_text(yaml.safe_dump(bad))

    result, _ = run(do="apply", config="C")
    assert result["ok"] is False and result["changed"] is False and result["step"] == "network devices"
    assert "Nothing was applied" in result["error"]
    assert router["ruleset"]() == before
    assert router["addresses"]("lan0") == ["10.88.1.1/24"]


# --- an apply held for confirmation (ROADMAP SEC-26) --------------------------------


def _held_apply_of_c(router):
    """A applied in full, then C -- another LAN address and rule -- applied
    from config.yaml and held for confirmation."""
    run, tmp = router["run"], router["tmp"]
    assert run(do="apply", config="A")[0] == {"ok": True}
    config_yaml = tmp / "config.yaml"
    config_yaml.write_text((tmp / "C.yaml").read_text())
    result, _ = run(do="cli", argv=["apply", "--confirm-within", "60", str(config_yaml)])
    assert result["code"] == 0
    assert json.loads((tmp / "apply-pending.json").read_text())["previous"] == (tmp / "A.yaml").read_text()
    assert router["addresses"]("lan0") == ["10.88.3.1/24"], "A's address stayed (FR-NEW-005)"
    assert "lan-out-c" in router["ruleset"]()
    return config_yaml


def _back_on_a(router, config_yaml):
    tmp = router["tmp"]
    ruleset = router["ruleset"]()
    assert "lan-out-a" in ruleset and "lan-out-c" not in ruleset
    assert router["addresses"]("lan0") == ["10.88.1.1/24"]
    assert config_yaml.read_text() == (tmp / "A.yaml").read_text()
    assert (tmp / "applied-config.yaml").read_text() == (tmp / "A.yaml").read_text()
    assert (tmp / "config.rejected.yaml").read_text() == (tmp / "C.yaml").read_text()
    assert not (tmp / "apply-pending.json").exists()
    alerts = [json.loads(line) for line in (tmp / "log" / "audit.log").read_text().splitlines()]
    assert any("was not confirmed" in (e.get("alert") or "") for e in alerts)


def test_an_unconfirmed_apply_is_reverted_on_a_real_kernel(router):
    config_yaml = _held_apply_of_c(router)
    result, _ = router["run"](do="cli", argv=["apply-revert", str(config_yaml)])
    assert result["code"] == 0
    _back_on_a(router, config_yaml)


def test_a_boot_with_an_apply_pending_comes_up_on_the_config_before_it(router):
    config_yaml = _held_apply_of_c(router)
    result, _ = router["run"](do="cli", argv=["apply", "--fail-closed", str(config_yaml)])
    assert result["code"] == 0
    _back_on_a(router, config_yaml)
