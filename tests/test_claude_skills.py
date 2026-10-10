"""The agent skills this repo hands to Claude Code stay reviewed.

`.claude/skills/` holds third-party prose that every contributor's agent
loads, and a plugin enabled in `.claude/settings.json` would pull in
third-party code. Both are a supply-chain surface (security-lessons G11, AGENTS.md "Never install anything
unpinned"), so the rules in `.claude/skills/VENDOR.md` are checked here: prose
only, every skill accounted for, install commands pinned, no plugins enabled.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKILLS = ROOT / ".claude" / "skills"
SETTINGS = ROOT / ".claude" / "settings.json"
VENDOR = SKILLS / "VENDOR.md"

SKILL_DIRS = sorted(p for p in SKILLS.iterdir() if p.is_dir())
NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")

# Vendored before this check existed; VENDOR.md names it as an open exception.
# Do not add to this list: pin the command in the skill instead.
KNOWN_UNPINNED = {
    ("generating-and-analyzing-sboms",
     "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh"),
    ("generating-and-analyzing-sboms",
     "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh"),
}


def frontmatter(skill_md: Path) -> dict[str, str]:
    text = skill_md.read_text(encoding="utf-8")
    assert text.startswith("---\n"), f"{skill_md}: no frontmatter"
    block = text.split("---\n", 2)[1]
    out = {}
    for line in block.splitlines():
        key, sep, value = line.partition(":")
        if sep and not line.startswith((" ", "\t")):
            out[key.strip()] = value.strip().strip('"')
    return out


def test_skills_exist():
    assert SKILL_DIRS, "no vendored skills found"


@pytest.mark.parametrize("skill", SKILL_DIRS, ids=lambda p: p.name)
def test_skill_name_matches_directory(skill):
    meta = frontmatter(skill / "SKILL.md")
    assert NAME_RE.match(meta.get("name", "")), meta.get("name")
    assert meta["name"] == skill.name
    assert meta.get("description")


@pytest.mark.parametrize("skill", SKILL_DIRS, ids=lambda p: p.name)
def test_skill_is_listed_in_vendor_md(skill):
    assert f"`{skill.name}`" in VENDOR.read_text(encoding="utf-8")


def test_skills_are_prose_only():
    """No upstream scripts, hooks or binaries: only Markdown and licences."""
    for path in SKILLS.rglob("*"):
        if path.is_dir():
            assert path.name not in {"scripts", "hooks", "bin"}, path
            continue
        assert path.suffix == ".md" or path.name == "LICENSE", path
        assert not path.stat().st_mode & 0o111, f"{path} is executable"


def test_skills_never_install_unpinned():
    """An install command a skill gives the agent names an exact version."""
    unpinned = re.compile(
        r"npm install -g (?![\w@/.-]+@\d)|pip install (?!-r)(?![\w.\[\],-]+==)"
        r"|cargo install (?!.*--version)|curl [^\n`]*\| *(?:ba)?sh"
    )
    offenders = []
    for skill in SKILL_DIRS:
        text = (skill / "SKILL.md").read_text(encoding="utf-8")
        offenders += [
            f"{skill.name}: {m.group(0)}"
            for m in unpinned.finditer(text)
            if (skill.name, m.group(0)) not in KNOWN_UNPINNED
        ]
    assert not offenders, offenders


def test_no_plugins_are_enabled():
    """Only vendored skills, which every session loads; no plugins (VENDOR.md,
    "Not taken"). Enabling one is a separate, reviewed decision."""
    if not SETTINGS.exists():
        return
    settings = json.loads(SETTINGS.read_text(encoding="utf-8"))
    for key in ("enabledPlugins", "extraKnownMarketplaces", "additionalMarketplaces"):
        assert not settings.get(key), key
