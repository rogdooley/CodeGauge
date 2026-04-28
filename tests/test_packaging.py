from __future__ import annotations

import tomllib
from pathlib import Path


def test_script_entrypoint_exists() -> None:
    pyproject = Path("pyproject.toml")
    data = tomllib.loads(pyproject.read_text())
    scripts = data["project"]["scripts"]
    assert scripts["codegauge"] == "codegauge.cli:app"
