from __future__ import annotations

import shutil
from pathlib import Path
from typing import Sequence

from .base import Scanner


class PHPStanScanner(Scanner):
    scanner_name = "phpstan"
    supported_languages = ["php"]

    def is_available(self) -> bool:
        return shutil.which("phpstan") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["phpstan", "analyse", str(project_path), "--error-format", "json", *self.extra_args]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files: Sequence[Path]) -> list[str]:
        if not files:
            return self.build_command(project_path)
        return ["phpstan", "analyse", *[str(path) for path in files], "--error-format", "json", *self.extra_args]
