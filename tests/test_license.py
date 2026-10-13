"""The project's licence files agree with each other.

FR_OS is AGPL-3.0-only with a plugin exception, and contributions come in
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


def test_exception_and_cla_are_where_the_docs_point():
    readme = (ROOT / "README.md").read_text()
    agents = (ROOT / "AGENTS.md").read_text()
    for name in ("LICENSE-EXCEPTION.md", "CLA.md"):
        assert (ROOT / name).is_file(), name
        assert f"]({name})" in readme, name
        assert f"]({name})" in agents, name
    exception = (ROOT / "LICENSE-EXCEPTION.md").read_text()
    assert "section 7" in exception


def test_legal_notice_covers_export_control_and_is_linked():
    legal = (ROOT / "LEGAL.md").read_text()
    assert "](LEGAL.md)" in (ROOT / "README.md").read_text()
    assert "## International Compliance & Export Control" in legal
    for url in ("https://www.sanctionsmap.eu/",
                "https://ofac.treasury.gov/sanctions-programs-and-country-information",
                "https://www.bis.gov/licensing/country-guidance"):
        assert f"]({url} " in legal, url
    assert "2021/821" in legal and '"AS IS"' in legal
