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
