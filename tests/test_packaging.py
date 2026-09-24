"""Every non-Python file under src/frfw must be declared as package data.

A regular `pip install /opt/frfw-src` (the live image's install hook) or
`pip install <release tarball>` (frfw.update) only copies .py files plus
whatever `[tool.setuptools.package-data]` lists -- an undeclared template
or data file works in a dev checkout and silently disappears on a real
install. Building a wheel here would need network access for the build
backend, so this checks the declaration itself instead.
"""

from __future__ import annotations

import fnmatch
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"


def _package_data() -> dict[str, list[str]]:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    return data["tool"]["setuptools"].get("package-data", {})


def _is_declared(path: Path, package_data: dict[str, list[str]]) -> bool:
    for package, patterns in package_data.items():
        package_dir = SRC / package.replace(".", "/")
        try:
            relative = path.relative_to(package_dir).as_posix()
        except ValueError:
            continue
        # setuptools globs don't cross directories with "*", same as fnmatch
        # on a path whose separators must match literally.
        if any(fnmatch.fnmatchcase(relative, pattern) and relative.count("/") == pattern.count("/")
               for pattern in patterns):
            return True
    return False


def test_every_non_python_file_is_package_data():
    package_data = _package_data()
    undeclared = [
        str(path.relative_to(REPO_ROOT))
        for path in (SRC / "frfw").rglob("*")
        if path.is_file()
        and path.suffix not in {".py", ".pyc"}
        and "__pycache__" not in path.parts
        and not _is_declared(path, package_data)
    ]
    assert undeclared == []


def test_webui_templates_are_declared():
    # The concrete regression: templates were missing from installed wheels.
    assert "templates/*.html" in _package_data()["frfw.webui"]
