from pathlib import Path

from fastapi.templating import Jinja2Templates

from frfw import codename_for

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# "0.1.0" -> "0.1.0 “Ice Breaker”" (the release codenames, see ROADMAP.md).
templates.env.filters["with_codename"] = (
    lambda version: f"{version} “{codename_for(version)}”" if codename_for(str(version)) else version
)
