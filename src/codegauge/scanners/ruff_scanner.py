from __future__ import annotations

import shutil
from pathlib import Path
from typing import Sequence

from .base import Scanner


class RuffScanner(Scanner):
    scanner_name = "ruff"
    supported_languages = ["python"]

    def is_available(self) -> bool:
        return shutil.which("ruff") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["ruff", "check", str(project_path), "--output-format", "json", "--exit-zero", *self.extra_args]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files: Sequence[Path]) -> list[str]:
        return [
            "ruff",
            "check",
            "--output-format",
            "json",
            "--exit-zero",
            *[str(path) for path in files],
            *self.extra_args,
        ]
