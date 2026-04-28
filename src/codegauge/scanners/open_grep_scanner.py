from __future__ import annotations

import shutil
from pathlib import Path

from .base import Scanner


class OpenGrepScanner(Scanner):
    scanner_name = "opengrep"
    supported_languages = ["python", "general"]

    def is_available(self) -> bool:
        return shutil.which("opengrep") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["opengrep", str(project_path), "--format", "sarif", *self.extra_args]
