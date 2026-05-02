from __future__ import annotations

import sys
from pathlib import Path

from .base import Scanner


class TerraformScanScanner(Scanner):
    scanner_name = "terraform_scan"
    supported_languages = ["general"]

    def is_available(self) -> bool:
        return True

    def build_command(self, project_path: Path) -> list[str]:
        script = r"""
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
files = list(root.rglob("*.tf"))
findings = []
for path in files[:500]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    rel = path.relative_to(root).as_posix()
    if re.search(r"(?mi)0\.0\.0\.0/0", text):
        findings.append({"rule_id": "INF.TF.OPEN_WORLD", "file": rel, "line": 1, "message": "Open world CIDR detected", "severity": "high"})
    if re.search(r"(?mi)public\s*=\s*true\b", text):
        findings.append({"rule_id": "INF.TF.PUBLIC_RESOURCE", "file": rel, "line": 1, "message": "Public resource exposure", "severity": "medium"})
    if re.search(r"(?mi)encrypted\s*=\s*false\b", text):
        findings.append({"rule_id": "INF.TF.ENCRYPTION_DISABLED", "file": rel, "line": 1, "message": "Encryption disabled", "severity": "high"})
print(json.dumps({"findings": findings, "scalar_metrics": {"terraform_file_count": len(files)}}))
"""
        return [sys.executable, "-c", script, str(project_path)]
