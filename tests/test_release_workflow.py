"""Who can make a signed FR_OS release (review v0.2.1 FR-NEW-001, FR-NEW-002).

The release signing key is the root of trust of every router's updates:
whatever it signs, routers install as root. So the workflow that uses it
is held to a few rules, checked here:

- the key is a secret of the `release` environment (approval by the
  owner, v* tags only -- set in the repository's settings) and only the
  jobs that run in that environment ask for it; the jobs that build and
  boot the image, and every test build on a branch, never see it;
- a release is built from exactly the commit its tag names;
- nothing may write to the repository but the job that publishes;
- every third-party action is pinned to a commit, not a movable tag.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "build-installer.yml"


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def _steps_text(job: dict) -> str:
    return yaml.safe_dump(job.get("steps", []))


def test_only_the_release_environments_jobs_ask_for_the_signing_key():
    jobs = _workflow()["jobs"]
    holders = {name for name, job in jobs.items() if "FROS_RELEASE_SIGNING_KEY" in _steps_text(job)}
    assert holders == {"sign-source", "publish"}
    for name in holders:
        assert jobs[name]["environment"] == "release", name
        assert jobs[name]["if"] == "${{ inputs.release_tag != '' }}", name  # never on a test build
    for name in set(jobs) - holders:
        assert "secrets." not in _steps_text(jobs[name]), name


def test_the_image_is_built_and_booted_without_the_key():
    jobs = _workflow()["jobs"]
    build = jobs["build"]
    assert "environment" not in build and "secrets." not in _steps_text(build)
    assert "build-live-image.sh" in _steps_text(build) and "qemu-boot-test.py" in _steps_text(build)


def test_a_release_is_built_from_the_commit_its_tag_names():
    gate = _workflow()["jobs"]["source"]["steps"][1]["run"]
    assert '"$GITHUB_REF" != "refs/tags/$RELEASE_TAG"' in gate
    assert 'tag_sha=$(git rev-parse "refs/tags/$RELEASE_TAG^{commit}")' in gate
    assert '"$tag_sha" != "$GITHUB_SHA"' in gate and '"$(git rev-parse HEAD)" != "$tag_sha"' in gate
    # ...before anything is built or signed: the first job, which every other needs.
    jobs = _workflow()["jobs"]
    assert jobs["sign-source"]["needs"] == "source" and "source" in jobs["build"]["needs"]


def test_only_the_publishing_job_may_write():
    workflow = _workflow()
    assert workflow["permissions"] == {"contents": "read"}
    writers = {name for name, job in workflow["jobs"].items() if job.get("permissions", {}).get("contents") == "write"}
    assert writers == {"publish"}


def test_every_action_is_pinned_to_a_commit():
    uses = re.findall(r"^\s*(?:- )?uses:\s*(\S+)", WORKFLOW.read_text(), re.M)
    assert uses
    for action in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", action), action
