import shutil
import subprocess

import pytest

from frfw.config import parse_config
from frfw.nft import RuntimeSets, build_ruleset

requires_nft = pytest.mark.skipif(shutil.which("nft") is None, reason="nft binary not installed")


def test_build_ruleset_contains_expected_rules(example_config_path):
    from frfw.config import load_config

    config = load_config(example_config_path)
    ruleset = build_ruleset(config)

    assert "table inet fr_os" in ruleset
    assert 'set wan_ifaces' in ruleset
    assert 'elements = { "eth0" }' in ruleset
    assert "policy drop;" in ruleset  # input/forward default-deny
    assert 'iifname @lan_ifaces tcp dport 22 counter accept comment "rule:allow-ssh-from-lan-to-router"' in ruleset
    assert "oifname @wan_ifaces masquerade" in ruleset
    assert "dnat ip to 10.0.2.10:443" in ruleset


def test_self_zone_rule_goes_to_input_not_forward(minimal_config_dict):
    minimal_config_dict["rules"].append(
        {"name": "ssh-to-router", "action": "accept", "from_zone": "lan", "to_zone": "self", "proto": "tcp", "dst_port": 22}
    )
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)

    input_chain = ruleset.split("chain input {")[1].split("chain forward {")[0]
    forward_chain = ruleset.split("chain forward {")[1]

    assert "dport 22" in input_chain
    assert "oifname" not in input_chain.split("dport 22")[0].split("\n")[-1]
    assert "dport 22" not in forward_chain


@requires_nft
def test_generated_ruleset_passes_nft_syntax_check(example_config_path):
    from frfw.config import load_config

    config = load_config(example_config_path)
    ruleset = build_ruleset(config)

    proc = subprocess.run(
        ["nft", "-c", "-f", "-"], input=ruleset, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr


@requires_nft
def test_minimal_ruleset_passes_nft_syntax_check(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)

    proc = subprocess.run(
        ["nft", "-c", "-f", "-"], input=ruleset, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr


def _set_block(ruleset: str, name: str) -> str:
    return ruleset.split(f"set {name} {{")[1].split("\n\t}")[0]


def test_ztna_sets_bind_a_device_by_address_and_mac(minimal_config_dict):
    """ROADMAP SEC-6: the device set holds address . MAC pairs, the
    tunnel set addresses; both are timed and runtime-only."""
    minimal_config_dict["ztna"] = {"enabled": True, "users": [{"username": "a", "password_hash": "x"}]}
    ruleset = build_ruleset(parse_config(minimal_config_dict))
    device = _set_block(ruleset, "authenticated_ztna_users")
    tunnel = _set_block(ruleset, "authenticated_ztna_tunnel")
    assert "type ipv4_addr . ether_addr" in device
    assert "type ipv4_addr\n" in tunnel
    for block in (device, tunnel):
        assert "flags dynamic,timeout" in block
        assert "timeout 28800s" in block  # default 8h
        assert "elements" not in block


def test_ztna_sets_are_declared_empty_while_ztna_is_off(minimal_config_dict):
    """A `require_ztna` rule left in the config must not name a missing
    set (the ruleset would fail to load); it matches nothing instead --
    and nothing carried in a RuntimeSets gets in while ZTNA is off."""
    runtime = RuntimeSets(ztna=(("10.0.0.20", "aa:bb:cc:dd:ee:01", 100), ("10.99.0.2", "", 100)))
    ruleset = build_ruleset(parse_config(minimal_config_dict), runtime=runtime)
    assert "set authenticated_ztna_users {" in ruleset and "set authenticated_ztna_tunnel {" in ruleset
    assert "10.0.0.20" not in ruleset and "10.99.0.2" not in ruleset


def test_ztna_sessions_are_carried_into_their_own_set(minimal_config_dict):
    minimal_config_dict["ztna"] = {"enabled": True, "users": [{"username": "a", "password_hash": "x"}]}
    runtime = RuntimeSets(ztna=(
        ("10.0.0.20", "aa:bb:cc:dd:ee:01", 100),
        ("10.99.0.2", "", 50),
        ("10.0.0.21", "aa:bb:cc:dd:ee:02", 0),          # expired
        ("10.0.0.22", "AA:BB;flush ruleset", 100),      # not a MAC: never reaches the script
    ))
    ruleset = build_ruleset(parse_config(minimal_config_dict), runtime=runtime)
    assert "elements = { 10.0.0.20 . aa:bb:cc:dd:ee:01 timeout 100s }" in _set_block(ruleset, "authenticated_ztna_users")
    assert "elements = { 10.99.0.2 timeout 50s }" in _set_block(ruleset, "authenticated_ztna_tunnel")
    assert "10.0.0.21" not in ruleset and "10.0.0.22" not in ruleset


def test_ztna_set_uses_configured_ttl(minimal_config_dict):
    minimal_config_dict["ztna"] = {
        "enabled": True,
        "session_ttl_seconds": 900,
        "users": [{"username": "a", "password_hash": "x"}],
    }
    config = parse_config(minimal_config_dict)
    assert "timeout 900s" in build_ruleset(config)


def test_require_ztna_rule_adds_saddr_match(minimal_config_dict):
    minimal_config_dict["ztna"] = {"enabled": True, "users": [{"username": "a", "password_hash": "x"}]}
    minimal_config_dict["rules"].append(
        {
            "name": "gated",
            "action": "accept",
            "from_zone": "lan",
            "to_zone": "wan",
            "require_ztna": True,
        }
    )
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)

    # One line per way a client can be signed in, and no address-only
    # match anywhere (ROADMAP SEC-6).
    gated = [line.strip() for line in ruleset.splitlines() if "rule:gated" in line]
    assert len(gated) == 2
    assert "ip saddr . ether saddr @authenticated_ztna_users" in gated[0]
    assert 'iifname "wg0" ip saddr @authenticated_ztna_tunnel' in gated[1]
    for line in gated:
        assert line.endswith('accept comment "rule:gated"')
    assert "ip saddr @authenticated_ztna_users" not in ruleset


def test_rule_without_require_ztna_has_no_saddr_match(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)
    rule_line = next(line for line in ruleset.splitlines() if "rule:lan-to-wan" in line)
    assert "authenticated_ztna_users" not in rule_line


def test_bruteforce_jail_set_always_rendered(minimal_config_dict):
    # The jail set is a
    # kernel-level defense that must exist regardless of what the user
    # configured -- there is no "off" switch for brute-force protection.
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)

    assert "set bruteforce_jail {" in ruleset
    assert "type ipv4_addr" in ruleset
    assert "flags timeout" in ruleset


def test_bruteforce_jail_drop_rule_is_first_rule_in_input_chain(minimal_config_dict):
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)

    input_chain = ruleset.split("chain input {")[1].split("chain forward {")[0]
    rule_lines = [
        line.strip()
        for line in input_chain.splitlines()
        if line.strip() and not line.strip().startswith(("policy", "type", "hook", "}"))
    ]

    assert rule_lines[0] == 'ip saddr @bruteforce_jail drop comment "bruteforce-jail"'
    assert rule_lines[1] == 'ip saddr @ids_quarantine drop comment "ids-quarantine"'
    # Must come before even the loopback accept, which is otherwise the
    # first rule in the chain.
    assert rule_lines[2] == 'iifname "lo" accept'


def test_ids_quarantine_also_cuts_forwarded_traffic(minimal_config_dict):
    # Review C-01: a quarantined host used to lose only the router itself;
    # its traffic through the router (the internet, other zones) went on.
    ruleset = build_ruleset(parse_config(minimal_config_dict))
    forward = ruleset.split("chain forward {")[1].split("chain output {")[0]
    lines = [l.strip() for l in forward.splitlines()
             if l.strip() and not l.strip().startswith(("type", "}"))]
    assert lines[0] == 'ip saddr @ids_quarantine drop comment "ids-quarantine-forward"'
    assert lines.index("ct state established,related accept") > 0


def test_ids_quarantine_set_always_rendered(minimal_config_dict):
    # Like the brute-force jail, the IDS
    # quarantine set is a kernel-level defense with no "off" switch --
    # it must exist regardless of whether ai_ids.enabled, since a
    # detection engine turned off later should not silently amnesty
    # already-quarantined hosts (see frfw.provision's own comment).
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)

    assert "set ids_quarantine {" in ruleset
    assert "type ipv4_addr" in ruleset
    assert "flags timeout" in ruleset


@requires_nft
def test_ztna_enabled_ruleset_passes_nft_syntax_check(minimal_config_dict):
    minimal_config_dict["ztna"] = {"enabled": True, "users": [{"username": "a", "password_hash": "x"}]}
    minimal_config_dict["rules"].append(
        {
            "name": "gated",
            "action": "accept",
            "from_zone": "lan",
            "to_zone": "wan",
            "require_ztna": True,
        }
    )
    config = parse_config(minimal_config_dict)
    ruleset = build_ruleset(config)

    proc = subprocess.run(
        ["nft", "-c", "-f", "-"], input=ruleset, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr


@requires_nft
def test_a_require_ztna_rule_loads_while_ztna_is_off(minimal_config_dict):
    """ROADMAP SEC-6: it used to name a set that wasn't declared, and the
    whole ruleset failed to load; now it names an empty one."""
    minimal_config_dict["rules"].append(
        {"name": "gated", "action": "accept", "from_zone": "lan", "to_zone": "wan", "require_ztna": True}
    )
    ruleset = build_ruleset(parse_config(minimal_config_dict))
    proc = subprocess.run(["nft", "-c", "-f", "-"], input=ruleset, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "elements" not in _set_block(ruleset, "authenticated_ztna_users")
    assert "elements" not in _set_block(ruleset, "authenticated_ztna_tunnel")


@requires_nft
@pytest.mark.reads_runtime_sets
@pytest.mark.skipif(__import__("os").geteuid() != 0, reason="loading a ruleset needs root")
def test_real_reload_keeps_bans_quarantines_and_sessions(minimal_config_dict, tmp_path):
    """Review FR-002 against the kernel: read the live sets, reload with a
    fresh ruleset carrying them, and everything is still there with its
    remaining time -- no separate restore step involved."""
    from frfw import bruteforce, ids_quarantine, provision, ztna

    state_path = tmp_path / "ztna-state.json"
    minimal_config_dict["ztna"] = {"enabled": True, "users": [{"username": "a", "password_hash": "x"}]}
    config = parse_config(minimal_config_dict)
    try:
        subprocess.run(["nft", "-f", "-"], input=build_ruleset(config), text=True, check=True)
        bruteforce.ban_ip("203.0.113.5", 600)
        ids_quarantine.quarantine_ip("10.0.0.9", 600)
        ztna.authorize_client("10.0.0.20", "aa:bb:cc:dd:ee:01", 600, "a", state_path=state_path)
        ztna.authorize_client("10.99.0.2", "", 600, "a", state_path=state_path)

        runtime = provision._read_runtime_sets(config)
        subprocess.run(["nft", "-f", "-"], input=build_ruleset(config, runtime=runtime), text=True, check=True)

        for read, ip in ((bruteforce.list_banned, "203.0.113.5"), (ids_quarantine.list_quarantined, "10.0.0.9")):
            left = dict(read()).get(ip)
            assert left is not None and 500 < left <= 600, (ip, read())
        sessions = {(ip, mac): left for ip, mac, left in ztna.list_authorized()}
        assert set(sessions) == {("10.0.0.20", "aa:bb:cc:dd:ee:01"), ("10.99.0.2", "")}, sessions
        assert all(500 < left <= 600 for left in sessions.values()), sessions
    finally:
        subprocess.run(["nft", "flush", "ruleset"], check=False)
