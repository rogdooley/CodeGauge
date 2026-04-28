from __future__ import annotations

import shutil
from pathlib import Path

from .base import Scanner


class BanditScanner(Scanner):
    scanner_name = "bandit"
    supported_languages = ["python"]

    def is_available(self) -> bool:
        return shutil.which("bandit") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["bandit", "-r", str(project_path), "-f", "json", "--exit-zero", *self.extra_args]
