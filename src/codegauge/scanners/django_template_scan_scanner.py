from __future__ import annotations

import sys
from pathlib import Path

from .base import Scanner


class DjangoTemplateScanScanner(Scanner):
    scanner_name = "django_template_scan"
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
templates = list(root.rglob("templates/**/*.html"))
findings = []
autoescape_re = re.compile(r"{%\\s*autoescape\\s+off\\s*%}", re.I)
csrf_re = re.compile(r"<form[^>]*>", re.I)
csrf_token_re = re.compile(r"{%\\s*csrf_token\\s*%}", re.I)

for path in templates[:1000]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    rel = path.relative_to(root).as_posix()
    autoescape_match = autoescape_re.search(text)
    if autoescape_match:
        findings.append(
            {
                "rule_id": "DJG.TPL.AUTOESCAPE_OFF",
                "file": rel,
                "line": text.count("\\n", 0, autoescape_match.start()) + 1,
                "message": "Template disables autoescape",
                "severity": "high",
            }
        )
    form_match = csrf_re.search(text)
    if form_match and not csrf_token_re.search(text):
        findings.append(
            {
                "rule_id": "DJG.TPL.CSRF_TOKEN_MISSING",
                "file": rel,
                "line": text.count("\\n", 0, form_match.start()) + 1,
                "message": "Form appears without csrf_token",
                "severity": "medium",
            }
        )

print(json.dumps({"findings": findings}))
"""
        return [sys.executable, "-c", script, str(project_path)]
