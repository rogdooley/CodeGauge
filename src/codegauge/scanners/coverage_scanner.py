from __future__ import annotations

import shutil
from pathlib import Path

from .base import Scanner


class CoverageScanner(Scanner):
    scanner_name = "coverage"
    supported_languages = ["python"]

    def is_available(self) -> bool:
        return shutil.which("coverage") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["coverage", "json", "-o", "-", *self.extra_args]
