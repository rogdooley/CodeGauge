from __future__ import annotations

import fnmatch
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
        selected_files = [path for path in files if not self._is_excluded(project_path, path)]
        return [
            "bandit",
            "-f",
            "json",
            "--exit-zero",
            *[str(path) for path in selected_files],
            *self.extra_args,
        ]

    def _is_excluded(self, project_path: Path, file_path: Path) -> bool:
        if not self.extra_args:
            return False
        excludes: list[str] = []
        args = list(self.extra_args)
        idx = 0
        while idx < len(args):
            arg = args[idx]
            if arg in {"-x", "--exclude"} and idx + 1 < len(args):
                excludes.extend(part.strip() for part in str(args[idx + 1]).split(",") if part.strip())
                idx += 2
                continue
            idx += 1
        if not excludes:
            return False
        try:
            rel = file_path.resolve().relative_to(project_path.resolve()).as_posix()
        except ValueError:
            rel = file_path.as_posix()
        name = file_path.name
        for pattern in excludes:
            normalized = pattern.strip().lstrip("./")
            if not normalized:
                continue
            if fnmatch.fnmatch(rel, normalized) or fnmatch.fnmatch(name, normalized):
                return True
            if "/" not in normalized and "*" not in normalized:
                if rel == normalized or rel.startswith(f"{normalized}/"):
                    return True
                if f"/{normalized}/" in f"/{rel}":
                    return True
        return False
