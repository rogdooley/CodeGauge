from __future__ import annotations

import sys
from pathlib import Path

from .base import Scanner


class DockerfileScanScanner(Scanner):
    scanner_name = "dockerfile_scan"
    supported_languages = ["general"]

    def is_available(self) -> bool:
        return True

    def build_command(self, project_path: Path) -> list[str]:
        script = """
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
files = list(root.rglob("Dockerfile")) + list(root.rglob("Containerfile"))
findings = []
for path in files[:400]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    rel = path.relative_to(root).as_posix()
    if re.search(r"(?mi)^\s*USER\s+root\b", text):
        findings.append({"rule_id": "INF.CONTAINER.USER_ROOT", "file": rel, "line": 1, "message": "Container runs as root", "severity": "high"})
    if not re.search(r"(?mi)^\s*HEALTHCHECK\b", text):
        findings.append({"rule_id": "INF.CONTAINER.HEALTHCHECK_MISSING", "file": rel, "line": 1, "message": "Missing HEALTHCHECK", "severity": "low"})
    if re.search(r"(?mi)^\s*ADD\s+", text):
        findings.append({"rule_id": "INF.CONTAINER.ADD_USAGE", "file": rel, "line": 1, "message": "Prefer COPY over ADD", "severity": "low"})
print(json.dumps({"findings": findings, "scalar_metrics": {"dockerfile_count": len(files)}}))
"""
        return [sys.executable, "-c", script, str(project_path)]
