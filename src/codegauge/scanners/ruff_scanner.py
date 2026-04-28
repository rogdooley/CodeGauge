from __future__ import annotations

import shutil
from pathlib import Path

from .base import Scanner


class RuffScanner(Scanner):
    scanner_name = "ruff"
    supported_languages = ["python"]

    def is_available(self) -> bool:
        return shutil.which("ruff") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["ruff", "check", str(project_path), "--output-format", "json", "--exit-zero", *self.extra_args]
