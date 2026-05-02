from __future__ import annotations

import sys
from pathlib import Path

from .base import Scanner


class DjangoSettingsScanScanner(Scanner):
    scanner_name = "django_settings_scan"
    supported_languages = ["python"]

    def is_available(self) -> bool:
        return True

    def build_command(self, project_path: Path) -> list[str]:
        script = """
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
settings = list(root.rglob("settings.py"))
findings = []
patterns = [
    ("DJG.SET.DEBUG_TRUE", re.compile(r"^\\s*DEBUG\\s*=\\s*True\\b", re.M), "DEBUG should be False in production", "high"),
    (
        "DJG.SET.ALLOWED_HOSTS_EMPTY",
        re.compile(r"^\\s*ALLOWED_HOSTS\\s*=\\s*\\[\\s*\\]\\s*$", re.M),
        "ALLOWED_HOSTS is empty",
        "medium",
    ),
    (
        "DJG.SET.SECURE_PROXY_SSL_HEADER_MISSING",
        re.compile(r"SECURE_PROXY_SSL_HEADER"),
        "SECURE_PROXY_SSL_HEADER not configured",
        "low",
    ),
]

for path in settings[:200]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    rel = path.relative_to(root).as_posix()
    for rule_id, pattern, message, severity in patterns:
        match = pattern.search(text)
        if rule_id == "DJG.SET.SECURE_PROXY_SSL_HEADER_MISSING":
            if not match:
                findings.append({"rule_id": rule_id, "file": rel, "line": 1, "message": message, "severity": severity})
            continue
        if match:
            line = text.count("\\n", 0, match.start()) + 1
            findings.append({"rule_id": rule_id, "file": rel, "line": line, "message": message, "severity": severity})

print(json.dumps({"findings": findings}))
"""
        return [sys.executable, "-c", script, str(project_path)]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files) -> list[str]:
        _ = files
        return self.build_command(project_path)
