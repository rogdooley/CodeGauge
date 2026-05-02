from __future__ import annotations

import shutil
from pathlib import Path
from typing import Sequence

from .base import Scanner


class GovulncheckScanner(Scanner):
    scanner_name = "govulncheck"
    supported_languages = ["go"]

    def is_available(self) -> bool:
        return shutil.which("govulncheck") is not None

    def build_command(self, project_path: Path) -> list[str]:
        _ = project_path
        return ["govulncheck", "-json", "./...", *self.extra_args]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files: Sequence[Path]) -> list[str]:
        del files
        return self.build_command(project_path)
