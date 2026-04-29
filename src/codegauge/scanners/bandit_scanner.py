from __future__ import annotations

import shutil
from pathlib import Path
from typing import Sequence

from .base import Scanner


class BanditScanner(Scanner):
    scanner_name = "bandit"
    supported_languages = ["python"]

    def is_available(self) -> bool:
        return shutil.which("bandit") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["bandit", "-r", str(project_path), "-f", "json", "--exit-zero", *self.extra_args]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files: Sequence[Path]) -> list[str]:
        return [
            "bandit",
            "-f",
            "json",
            "--exit-zero",
            *[str(path) for path in files],
            *self.extra_args,
        ]
