from __future__ import annotations

import sys
from pathlib import Path

from .base import Scanner


class DjangoCheckDeployScanner(Scanner):
    scanner_name = "django_check_deploy"
    supported_languages = ["python"]

    def is_available(self) -> bool:
        return True

    def build_command(self, project_path: Path) -> list[str]:
        script = """
import json
import os
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
manage = root / "manage.py"
if not manage.exists():
    print(json.dumps({"returncode": 0, "stdout": "", "stderr": "", "tool": "django", "command": []}))
    raise SystemExit(0)

env = dict(os.environ)
env.setdefault("PYTHONUNBUFFERED", "1")
completed = subprocess.run(
    [sys.executable, "manage.py", "check", "--deploy", "--fail-level", "WARNING"],
    cwd=root,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    env=env,
    check=False,
)
payload = {
    "returncode": completed.returncode,
    "stdout": completed.stdout,
    "stderr": completed.stderr,
    "tool": "django",
    "command": ["manage.py", "check", "--deploy", "--fail-level", "WARNING"],
}
print(json.dumps(payload))
"""
        return [sys.executable, "-c", script, str(project_path)]
