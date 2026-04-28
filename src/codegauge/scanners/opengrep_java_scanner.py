from __future__ import annotations

import shutil
from pathlib import Path

from .base import Scanner


class OpenGrepJavaScanner(Scanner):
    scanner_name = "opengrep_java"
    supported_languages = ["java"]

    def is_available(self) -> bool:
        return shutil.which("opengrep") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["opengrep", str(project_path), "--lang", "java", "--format", "sarif", *self.extra_args]

