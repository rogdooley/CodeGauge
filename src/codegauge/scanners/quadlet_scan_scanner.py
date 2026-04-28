from __future__ import annotations

import sys
from pathlib import Path

from .base import Scanner


class QuadletScanScanner(Scanner):
    scanner_name = "quadlet_scan"
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
extensions = ("*.container", "*.kube", "*.volume", "*.network")
files = []
for pattern in extensions:
    files.extend(root.rglob(pattern))
findings = []
for path in files[:300]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    rel = path.relative_to(root).as_posix()
    if re.search(r"(?mi)^\s*PublishPort\s*=\s*", text):
        findings.append({"rule_id": "INF.QUADLET.PORT_EXPOSED", "file": rel, "line": 1, "message": "Published port in quadlet", "severity": "medium"})
    if re.search(r"(?mi)^\s*User\s*=\s*root\b", text):
        findings.append({"rule_id": "INF.QUADLET.ROOT_USER", "file": rel, "line": 1, "message": "Quadlet configured with root user", "severity": "high"})
print(json.dumps({"findings": findings, "scalar_metrics": {"quadlet_count": len(files)}}))
"""
        return [sys.executable, "-c", script, str(project_path)]
