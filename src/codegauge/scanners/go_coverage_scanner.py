from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Sequence

from .base import Scanner


class GoCoverageScanner(Scanner):
    scanner_name = "go_coverage"
    supported_languages = ["go"]

    def is_available(self) -> bool:
        return shutil.which("go") is not None

    def build_command(self, project_path: Path) -> list[str]:
        script = """
import json
import subprocess
import tempfile
from pathlib import Path

root = Path(__import__('sys').argv[1])
with tempfile.NamedTemporaryFile(prefix='codegauge-go-', suffix='.cov', delete=False) as handle:
    profile = Path(handle.name)

test_run = subprocess.run(
    ['go', 'test', './...', f'-coverprofile={profile}', '-covermode=count'],
    cwd=root,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    check=False,
)

if test_run.returncode != 0:
    print(json.dumps({'totals': {'percent_covered': 0.0}}))
    raise SystemExit(0)

cover_run = subprocess.run(
    ['go', 'tool', 'cover', '-func', str(profile)],
    cwd=root,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    check=False,
)

percent = 0.0
for line in (cover_run.stdout or '').splitlines():
    low = line.strip().lower()
    if low.startswith('total:') and '%' in line:
        token = line.split()[-1].replace('%', '')
        try:
            percent = float(token)
        except ValueError:
            percent = 0.0
        break
print(json.dumps({'totals': {'percent_covered': percent}}))
"""
        return [sys.executable, "-c", script, str(project_path), *self.extra_args]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files: Sequence[Path]) -> list[str]:
        del files
        return self.build_command(project_path)
