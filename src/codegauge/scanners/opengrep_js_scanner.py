from __future__ import annotations

import shutil
from pathlib import Path

from .base import Scanner


class OpenGrepJSScanner(Scanner):
    scanner_name = "opengrep_js"
    supported_languages = ["javascript", "typescript"]

    def is_available(self) -> bool:
        return shutil.which("opengrep") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["opengrep", str(project_path), "--lang", "javascript", "--format", "sarif", *self.extra_args]
