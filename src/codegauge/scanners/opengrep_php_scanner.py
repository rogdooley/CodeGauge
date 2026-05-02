from __future__ import annotations

import shutil
from pathlib import Path
from typing import Sequence

from .base import Scanner


class OpenGrepPHPScanner(Scanner):
    scanner_name = "opengrep_php"
    supported_languages = ["php"]

    def is_available(self) -> bool:
        return shutil.which("opengrep") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["opengrep", str(project_path), "--lang", "php", "--format", "sarif", *self.extra_args]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files: Sequence[Path]) -> list[str]:
        if not files:
            return self.build_command(project_path)
        return ["opengrep", "scan", "--sarif", *[str(path) for path in files], *self.extra_args]
