from __future__ import annotations

import shutil
from pathlib import Path

from .base import Scanner


class VultureScanner(Scanner):
    scanner_name = "vulture"
    supported_languages = ["python"]

    def is_available(self) -> bool:
        return shutil.which("vulture") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["vulture", str(project_path), "--json", *self.extra_args]
