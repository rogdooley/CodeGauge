from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .base import Scanner


class NpmAuditScanner(Scanner):
    scanner_name = "npm_audit"
    supported_languages = ["javascript", "typescript"]

    def is_available(self) -> bool:
        return any(shutil.which(binary) is not None for binary in ("npm", "pnpm", "yarn"))

    def build_command(self, project_path: Path) -> list[str]:
        script = """
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
extra_args = sys.argv[2:]

commands = []
if (root / "pnpm-lock.yaml").exists():
    commands.append(["pnpm", "audit", "--json"])
if (root / "yarn.lock").exists():
    commands.append(["yarn", "npm", "audit", "--recursive", "--json"])
if (root / "package-lock.json").exists() or not commands:
    commands.append(["npm", "audit", "--json"])

result = {
    "tool": "none",
    "stdout": "",
    "stderr": "",
    "returncode": 0,
    "schema": "none",
}

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
    stdout = completed.stdout or ""
    parsed_ok = False
    schema = "unknown"
    if stdout.strip():
        try:
            payload = json.loads(stdout)
            if isinstance(payload, dict):
                if isinstance(payload.get("vulnerabilities"), dict):
                    schema = "npm-v2"
                elif isinstance(payload.get("advisories"), dict):
                    schema = "npm-v1"
                elif isinstance(payload.get("data"), dict):
                    schema = "yarn-audit"
                elif isinstance(payload.get("actions"), list):
                    schema = "npm-actions"
                parsed_ok = True
        except json.JSONDecodeError:
            parsed_ok = False
    result = {
        "tool": command[0],
        "stdout": stdout,
        "stderr": completed.stderr or "",
        "returncode": completed.returncode,
        "schema": schema,
    }
    if parsed_ok:
        break

print(json.dumps(result))
"""
        _ = os.environ
        return [sys.executable, "-c", script, str(project_path), *self.extra_args]
