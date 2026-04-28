from __future__ import annotations

from pathlib import Path

from .base import Scanner


import shutil


class PyrightScanner(Scanner):
    scanner_name = "pyright"
    supported_languages = ["python", "typescript", "javascript"]

    def is_available(self) -> bool:
        return shutil.which("pyright") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["pyright", str(project_path), "--outputjson", *self.extra_args]
