from __future__ import annotations

import shutil
from pathlib import Path

from .base import Scanner


class ESLintScanner(Scanner):
    scanner_name = "eslint"
    supported_languages = ["javascript", "typescript"]

    def is_available(self) -> bool:
        return shutil.which("eslint") is not None

    def build_command(self, project_path: Path) -> list[str]:
        _ = project_path
        targets = ["."]
        return [
            "eslint",
            *targets,
            "--format",
            "json",
            "--no-error-on-unmatched-pattern",
            "--ext",
            ".js,.jsx,.ts,.tsx",
            *self.extra_args,
        ]
