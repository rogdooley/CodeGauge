from __future__ import annotations

import shutil
import sys
from pathlib import Path

from .base import Scanner


class TypeScriptDiagnosticsScanner(Scanner):
    scanner_name = "typescript_diagnostics"
    supported_languages = ["typescript"]

    def is_available(self) -> bool:
        return shutil.which("tsc") is not None or shutil.which("npx") is not None

    def build_command(self, project_path: Path) -> list[str]:
        script = """
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
extra_args = sys.argv[2:]
tsconfig = root / "tsconfig.json"

commands = []
if tsconfig.exists():
    commands.append(["tsc", "--pretty", "false", "--noEmit", "--skipLibCheck", "--project", str(tsconfig)])
commands.append(["tsc", "--pretty", "false", "--noEmit", "--skipLibCheck"])
commands.append(["npx", "tsc", "--pretty", "false", "--noEmit", "--skipLibCheck"])

result = {"tool": "none", "command": [], "stdout": "", "stderr": "", "returncode": 0}
for command in commands:
    try:
        completed = subprocess.run(
            [*command, *extra_args],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        continue
    result = {
        "tool": command[0],
        "command": command,
        "stdout": completed.stdout or "",
        "stderr": completed.stderr or "",
        "returncode": completed.returncode,
    }
    break

print(json.dumps(result))
"""
        return [sys.executable, "-c", script, str(project_path), *self.extra_args]
