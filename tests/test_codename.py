"""Release codenames (ROADMAP.md, "Release cycle & codenames")."""

from __future__ import annotations

import pytest

from frfw import __codename__, __version__, codename_for
from frfw.cli import main


@pytest.mark.parametrize(
    ("version", "codename"),
    [
        ("0.1.0", "Ice Breaker"),
        ("v0.9.12", "Ice Breaker"),
        ("1.0.0", "Ice Breaker"),  # the Ice Breaker range ends with 1.0.0
        ("1.0.1", "Idun"),
        ("1.7.0", "Idun"),
        ("2.0.0", "Ivar"),
        ("3.4.5", "Inari"),
        ("v4.0.0", "Ingemar"),
        ("5.0.0", None),  # not named yet
        ("1.0", None),
        ("latest", None),
    ],
)
def test_codename_for(version, codename):
    assert codename_for(version) == codename


def test_installed_version_has_a_codename():
    assert __codename__ == codename_for(__version__) is not None


def test_cli_version_flag_shows_the_codename(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f'FR_OS {__version__} "{__codename__}"'
