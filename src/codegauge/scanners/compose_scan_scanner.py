from __future__ import annotations

import sys
from pathlib import Path

from .base import Scanner


class ComposeScanScanner(Scanner):
    scanner_name = "compose_scan"
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
patterns = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
files = []
for name in patterns:
    files.extend(root.rglob(name))
findings = []
for path in files[:300]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    rel = path.relative_to(root).as_posix()
    if re.search(r"(?mi)^\s*privileged:\s*true\b", text):
        findings.append({"rule_id": "INF.COMPOSE.PRIVILEGED", "file": rel, "line": 1, "message": "Privileged container enabled", "severity": "high"})
    if re.search(r"(?mi)^\s*ports:\s*$", text):
        findings.append({"rule_id": "INF.COMPOSE.PORT_EXPOSED", "file": rel, "line": 1, "message": "Ports exposed to host", "severity": "medium"})
    if re.search(r"(?mi)^\s*network_mode:\s*host\b", text):
        findings.append({"rule_id": "INF.COMPOSE.HOST_NETWORK", "file": rel, "line": 1, "message": "Host network mode enabled", "severity": "high"})
print(json.dumps({"findings": findings, "scalar_metrics": {"compose_file_count": len(files)}}))
"""
        return [sys.executable, "-c", script, str(project_path)]
