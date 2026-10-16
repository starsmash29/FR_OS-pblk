"""ROADMAP SEC-30: a rule is placed where it takes effect, and the admin
can move it up or down the list.

The firewall takes the first matching rule, so appending a new rule to the
end -- behind a broader one that decides the other way -- means it never
runs (security-lessons K2). `rule_order` finds that shadowing rule from the
same `covers` test the rule check uses, and reorders the raw rule dicts in
place; `swap`/`move_before` back the Rules screen's buttons and the
`firewall-cli rule-move` command.
"""

from __future__ import annotations

from frfw import rule_order
from frfw.config import parse_config


def _config(rules, **extra) -> dict:
    return {
        "version": 1, "hostname": "router", "zones": {"wan": {}, "lan": {}},
        "interfaces": {"wan": {"device": "eth0", "zone": "wan"},
                       "lan": {"device": "eth1", "zone": "lan", "address": "192.168.1.1/24"}},
        "rules": rules, "nat": {"masquerade": [{"out_zone": "wan"}]}, **extra,
    }


def _place(rules):
    """Run placement on the raw dicts the way the Rules screen does -- the
    last rule is the one just added -- and return (placed_before, order)."""
    raw = _config(rules)
    config = parse_config(raw)
    placed = rule_order.place(raw["rules"], rules[-1]["name"], config)
    return placed, [r["name"] for r in raw["rules"]]


# -- placement ---------------------------------------------------------------------------------


def test_deny_added_behind_a_broad_accept_moves_before_it():
    placed, order = _place([
        {"name": "lan-to-wan", "action": "accept", "from_zone": "lan", "to_zone": "wan"},
        {"name": "block-host", "action": "drop", "from_zone": "lan", "to_zone": "wan",
         "src_address": "192.168.1.50/32"},
    ])
    assert placed == "lan-to-wan"
    assert order == ["block-host", "lan-to-wan"]


def test_accept_added_behind_a_broad_deny_moves_before_it():
    placed, order = _place([
        {"name": "block-lan", "action": "drop", "from_zone": "lan", "to_zone": "wan"},
        {"name": "allow-dns", "action": "accept", "from_zone": "lan", "to_zone": "wan",
         "proto": "udp", "dst_port": 53},
    ])
    assert placed == "block-lan"
    assert order == ["allow-dns", "block-lan"]


def test_no_conflict_stays_at_the_end():
    placed, order = _place([
        {"name": "lan-to-wan", "action": "accept", "from_zone": "lan", "to_zone": "wan"},
        {"name": "dmz-rule", "action": "drop", "from_zone": "lan", "to_zone": "self",
         "proto": "tcp", "dst_port": 22},
    ])
    assert placed is None
    assert order == ["lan-to-wan", "dmz-rule"]


def test_same_action_does_not_shadow():
    # A broader accept before a narrower accept is redundant, not a hole:
    # placement only moves a rule that would be decided the other way.
    placed, order = _place([
        {"name": "lan-to-wan", "action": "accept", "from_zone": "lan", "to_zone": "wan"},
        {"name": "lan-dns", "action": "accept", "from_zone": "lan", "to_zone": "wan",
         "proto": "udp", "dst_port": 53},
    ])
    assert placed is None
    assert order == ["lan-to-wan", "lan-dns"]


def test_already_ahead_of_the_shadower_is_left_alone():
    raw = _config([
        {"name": "block-host", "action": "drop", "from_zone": "lan", "to_zone": "wan",
         "src_address": "192.168.1.50/32"},
        {"name": "lan-to-wan", "action": "accept", "from_zone": "lan", "to_zone": "wan"},
    ])
    placed = rule_order.place(raw["rules"], "block-host", parse_config(raw))
    assert placed is None
    assert [r["name"] for r in raw["rules"]] == ["block-host", "lan-to-wan"]


def test_gated_accept_added_behind_a_plain_accept_moves_before_it():
    # SEC-6/FND-1d: a plain accept before a ZTNA-gated accept would let the
    # traffic through ungated, so the gate never runs -- the gated rule goes
    # in front even though both are "accept".
    placed, order = _place([
        {"name": "lan-to-wan", "action": "accept", "from_zone": "lan", "to_zone": "wan"},
        {"name": "gated", "action": "accept", "from_zone": "lan", "to_zone": "wan",
         "proto": "tcp", "dst_port": 8446, "require_ztna": True},
    ])
    assert placed == "lan-to-wan"
    assert order == ["gated", "lan-to-wan"]


def test_the_full_ipv6_ztna_scenario_orders_itself_by_placement():
    # The boot test's three rules (ROADMAP FND-1d, 1d-3), added through the
    # Rules screen one by one: placement alone puts all three ahead of the
    # broad lan-to-wan accept, with the gated accept before its closing drop.
    raw = _config([{"name": "lan-to-wan", "action": "accept", "from_zone": "lan", "to_zone": "wan"}])
    for rule in (
        {"name": "drop-v6", "action": "drop", "from_zone": "lan", "to_zone": "wan",
         "proto": "tcp", "dst_port": 8445},
        {"name": "gated", "action": "accept", "from_zone": "lan", "to_zone": "wan",
         "proto": "tcp", "dst_port": 8446, "require_ztna": True},
        {"name": "gated-closed", "action": "drop", "from_zone": "lan", "to_zone": "wan",
         "proto": "tcp", "dst_port": 8446},
    ):
        raw["rules"].append(rule)
        rule_order.place(raw["rules"], rule["name"], parse_config(raw))
    assert [r["name"] for r in raw["rules"]] == ["drop-v6", "gated", "gated-closed", "lan-to-wan"]


def test_input_and_forward_chains_do_not_shadow_each_other():
    # A forward-chain accept cannot shadow an input-chain deny: they run in
    # different nft chains.
    placed, order = _place([
        {"name": "fwd-all", "action": "accept", "from_zone": "lan", "to_zone": "wan"},
        {"name": "to-router", "action": "drop", "from_zone": "lan", "to_zone": "self",
         "proto": "tcp", "dst_port": 22},
    ])
    assert placed is None
    assert order == ["fwd-all", "to-router"]


# -- swap --------------------------------------------------------------------------------------


def _raw(names):
    return [{"name": n, "action": "accept"} for n in names]


def test_swap_up_and_down():
    rules = _raw(["a", "b", "c"])
    out, msg = rule_order.swap(rules, "b", "up")
    assert [r["name"] for r in out] == ["b", "a", "c"]
    assert "up" in msg
    out, _ = rule_order.swap(rules, "b", "down")
    assert [r["name"] for r in out] == ["a", "c", "b"]
    # swap does not mutate the input list
    assert [r["name"] for r in rules] == ["a", "b", "c"]


def test_swap_at_the_edges_refuses():
    rules = _raw(["a", "b", "c"])
    out, msg = rule_order.swap(rules, "a", "up")
    assert out is None and "top" in msg
    out, msg = rule_order.swap(rules, "c", "down")
    assert out is None and "bottom" in msg


def test_swap_unknown_rule():
    out, msg = rule_order.swap(_raw(["a", "b"]), "z", "up")
    assert out is None and "No such rule" in msg


# -- move_before -------------------------------------------------------------------------------


def test_move_before():
    out, msg = rule_order.move_before(_raw(["a", "b", "c"]), "c", "a")
    assert [r["name"] for r in out] == ["c", "a", "b"]
    assert "before" in msg


def test_move_before_itself_and_missing():
    rules = _raw(["a", "b"])
    out, msg = rule_order.move_before(rules, "a", "a")
    assert out is None and "itself" in msg
    out, msg = rule_order.move_before(rules, "a", "z")
    assert out is None and "No such rule 'z'" in msg
    out, msg = rule_order.move_before(rules, "z", "a")
    assert out is None and "No such rule 'z'" in msg
