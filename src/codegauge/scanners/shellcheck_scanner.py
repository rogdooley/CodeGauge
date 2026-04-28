from __future__ import annotations

import shutil
import sys
from pathlib import Path

from .base import Scanner


class ShellCheckScanner(Scanner):
    scanner_name = "shellcheck"
    supported_languages = ["general"]

    def is_available(self) -> bool:
        return shutil.which("shellcheck") is not None

    def build_command(self, project_path: Path) -> list[str]:
        script = """
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
shell_files = [str(path) for path in root.rglob("*.sh")][:500]
if not shell_files:
    print("[]")
    raise SystemExit(0)
completed = subprocess.run(
    ["shellcheck", "--format", "json", "--external-sources", "--severity", "style", "-x", *shell_files, *sys.argv[2:]],
    cwd=root,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    check=False,
)
print(completed.stdout or "[]")
"""
        _ = project_path
        return [sys.executable, "-c", script, str(project_path), *self.extra_args]
