from pathlib import Path

import pytest

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture
def example_config_path() -> Path:
    return EXAMPLES_DIR / "config.yaml"


@pytest.fixture
def minimal_config_dict() -> dict:
    return {
        "version": 1,
        "hostname": "test-router",
        "interfaces": {
            "wan": {"device": "eth0", "zone": "wan"},
            "lan": {"device": "eth1", "zone": "lan"},
        },
        "zones": {"wan": {}, "lan": {}},
        "rules": [
            {"name": "lan-to-wan", "action": "accept", "from_zone": "lan", "to_zone": "wan"},
        ],
        "nat": {"masquerade": [{"out_zone": "wan"}]},
    }


@pytest.fixture
def dhcp_config_dict(minimal_config_dict) -> dict:
    """`minimal_config_dict`, but the LAN interface has a static address
    (device set to "lo" so real `kea-dhcp4 -t` checks -- which validate
    that listed interfaces actually exist -- pass in any test environment)
    and a DHCP pool for it."""
    minimal_config_dict["interfaces"]["lan"]["device"] = "lo"
    minimal_config_dict["interfaces"]["lan"]["address"] = "10.0.0.1/24"
    minimal_config_dict["dhcp"] = {
        "lan": {
            "range_start": "10.0.0.100",
            "range_end": "10.0.0.200",
            "dns_servers": ["1.1.1.1"],
            "reservations": [
                {"mac": "aa:bb:cc:dd:ee:ff", "address": "10.0.0.50", "hostname": "nas"},
            ],
        }
    }
    return minimal_config_dict
