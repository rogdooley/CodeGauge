from __future__ import annotations

import shutil
from pathlib import Path
from typing import Sequence

from .base import Scanner


class PHPCSScanner(Scanner):
    scanner_name = "phpcs"
    supported_languages = ["php"]

    def is_available(self) -> bool:
        return shutil.which("phpcs") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["phpcs", str(project_path), "--report=json", *self.extra_args]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files: Sequence[Path]) -> list[str]:
        if not files:
            return self.build_command(project_path)
        return ["phpcs", *[str(path) for path in files], "--report=json", *self.extra_args]
