"""The project's licence files agree with each other.

FR_OS is AGPL-3.0-only with no exceptions, and contributions come in
under the CLA. These checks keep the LICENSE text, the package metadata and
the files the README and AGENTS.md point to from drifting apart.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_license_is_the_agplv3_text():
    text = (ROOT / "LICENSE").read_text()
    assert text.lstrip().startswith("GNU AFFERO GENERAL PUBLIC LICENSE")
    assert "Version 3, 19 November 2007" in text
    assert "13. Remote Network Interaction; Use with the GNU General Public License." in text
    assert "Apache License" not in text


def test_package_metadata_names_the_same_license():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert meta["license"] == {"text": "AGPL-3.0-only"}


def test_cla_is_where_the_docs_point():
    readme = (ROOT / "README.md").read_text()
    agents = (ROOT / "AGENTS.md").read_text()
    assert (ROOT / "CLA.md").is_file()
    assert "](CLA.md)" in readme
    assert "](CLA.md)" in agents


def test_no_license_exception():
    """Pure AGPLv3: no additional permissions for other-licensed plugins
    (owner's decision, 2026-10-13), and no doc still points to one."""
    assert not (ROOT / "LICENSE-EXCEPTION.md").exists()
    for name in ("README.md", "AGENTS.md", "LEGAL.md", "ARCHITECTURE.md"):
        assert "LICENSE-EXCEPTION" not in (ROOT / name).read_text(), name


def test_trademark_and_contribution_rules():
    legal = (ROOT / "LEGAL.md").read_text()
    agents = (ROOT / "AGENTS.md").read_text()
    assert "### 3. Trademarks & Contributions" in legal
    assert "**Trademarks.**" in legal and "**Contributions.**" in legal
    assert "does not take compliance auditing features" in agents
    assert "[LEGAL.md](LEGAL.md), section 3" in agents


def test_legal_notice_covers_export_control_and_is_linked():
    legal = (ROOT / "LEGAL.md").read_text()
    assert "](LEGAL.md)" in (ROOT / "README.md").read_text()
    assert "## International Compliance & Export Control" in legal
    for url in ("https://www.sanctionsmap.eu/",
                "https://ofac.treasury.gov/sanctions-programs-and-country-information",
                "https://www.bis.gov/licensing/country-guidance"):
        assert f"]({url} " in legal, url
    assert "2021/821" in legal and '"AS IS"' in legal
