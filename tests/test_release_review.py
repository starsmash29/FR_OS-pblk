"""Security-lessons J2: no release without an adversarial review on
record -- two different models, the reviewed commit part of the release
and newer than the previous one, no critical/high finding left open.
Checked by scripts/check_release_review.py, which the release workflow
runs before building."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("check_release_review", ROOT / "scripts" / "check_release_review.py")
crr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(crr)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "a").write_text("1")
    _git(tmp_path, "add", "a")
    _git(tmp_path, "commit", "-qm", "first")
    _git(tmp_path, "tag", "v0.1.0")
    (tmp_path / "a").write_text("2")
    _git(tmp_path, "commit", "-qam", "second")
    (tmp_path / "docs" / "reviews").mkdir(parents=True)
    return tmp_path


def _record(repo: Path, *, commit=None, models="Model A, Model B", rows=None) -> None:
    commit = commit or _git(repo, "rev-parse", "HEAD")
    rows = rows if rows is not None else ["| R1 | high | login bypass | fixed in abc123 | A #1, B #4 |",
                                          "| R2 | low | typo | accepted: cosmetic | B #9 |"]
    (repo / "docs" / "reviews" / "v0.2.0.md").write_text("\n".join([
        "# Adversarial review – v0.2.0", "",
        f"- **Reviewed commit:** `{commit}`", f"- **Models:** {models}", "",
        "| ID | Severity | Finding | Status | Sources |", "|---|---|---|---|---|", *rows, ""]))


def test_a_complete_record_passes(repo):
    _record(repo)
    assert crr.check("0.2.0", repo) == []
    assert crr.check("v0.2.0", repo) == []


def test_no_record_no_release(repo):
    assert "is missing" in crr.check("0.2.0", repo)[0]


def test_one_model_is_not_enough(repo):
    _record(repo, models="Model A, model a")
    assert any("two different models" in p for p in crr.check("0.2.0", repo))


@pytest.mark.parametrize("status", ["open", "reported", "needs verification", ""])
def test_an_open_high_finding_blocks(repo, status):
    _record(repo, rows=[f"| R1 | high | login bypass | {status} | A #1 |"])
    assert any("open high finding R1" in p for p in crr.check("0.2.0", repo))


def test_open_medium_findings_dont_block(repo):
    _record(repo, rows=["| R1 | medium | slow page | open | A #1 |"])
    assert crr.check("0.2.0", repo) == []


def test_the_review_must_be_of_this_release(repo):
    first = _git(repo, "rev-list", "--max-parents=0", "HEAD")
    _record(repo, commit=first)  # the v0.1.0 commit: before the previous release
    assert any("before the previous release v0.1.0" in p for p in crr.check("0.2.0", repo))
    _git(repo, "checkout", "-qb", "side", first)
    (repo / "b").write_text("x")
    _git(repo, "add", "b")
    _git(repo, "commit", "-qm", "side")
    side = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "main")
    _record(repo, commit=side)  # never merged into the release
    assert any("not part of this release" in p for p in crr.check("0.2.0", repo))
    _record(repo, commit="0" * 40)
    assert any("doesn't exist" in p for p in crr.check("0.2.0", repo))


def test_a_table_is_required(repo):
    (repo / "docs" / "reviews" / "v0.2.0.md").write_text(
        f"- **Reviewed commit:** {_git(repo, 'rev-parse', 'HEAD')}\n- **Models:** A, B\n\nNothing found.\n")
    assert any("findings table" in p for p in crr.check("0.2.0", repo))


def test_the_template_is_the_documented_format():
    text = (ROOT / "docs" / "reviews" / "TEMPLATE.md").read_text()
    assert crr._field(text, "Models") and crr._field(text, "Reviewed commit")
    assert [r["severity"] for r in crr._findings(text)] == ["high", "medium", "low"]


def test_the_release_workflow_runs_it_first():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "build-installer.yml").read_text())
    steps = workflow["jobs"]["build"]["steps"]
    assert steps[0]["with"]["fetch-depth"] == 0
    assert "check_release_review.py" in steps[1]["run"] and steps[1]["if"] == "${{ inputs.release_tag != '' }}"
