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
form_re = re.compile(r"<form\\b(?P<attrs>[^>]*)>(?P<body>.*?)</form\\s*>", re.I | re.S)
method_re = re.compile(r"\\bmethod\\s*=\\s*([\\\"'])?\\s*(?P<method>[a-zA-Z]+)\\s*\\1", re.I)
csrf_evidence_res = [
    re.compile(r"{%\\s*csrf_token\\s*%}", re.I),
    re.compile(r"{{\\s*csrf_token\\s*}}", re.I),
    re.compile(r"{{\\s*csrf_input\\s*\\(\\s*\\)\\s*}}", re.I),
    re.compile(r"<input[^>]*type\\s*=\\s*([\\\"'])hidden\\1[^>]*name\\s*=\\s*([\\\"'])csrf_token\\2", re.I),
    re.compile(r"<input[^>]*name\\s*=\\s*([\\\"'])csrf_token\\1[^>]*type\\s*=\\s*([\\\"'])hidden\\2", re.I),
    re.compile(r"{%\\s*include\\s+[\\\"'][^\\\"']*csrf[^\\\"']*[\\\"']", re.I),
    re.compile(r"{%\\s*from\\s+[\\\"'][^\\\"']+[\\\"']\\s+import\\s+[^%]*csrf", re.I),
    re.compile(r"{{[^}]*csrf[^}]*\\(\\s*\\)\\s*}}", re.I),
]

for path in templates[:1000]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    rel = path.relative_to(root).as_posix()
    rel_lower = rel.lower()
    if any(part in rel_lower for part in ("/test", "/tests", "/docs", "/doc", "/examples", "/example")):
        continue

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

    for form_match in form_re.finditer(text):
        attrs = form_match.group("attrs") or ""
        method_match = method_re.search(attrs)
        method = (method_match.group("method") if method_match else "get").lower()
        if method != "post":
            continue

        form_block = form_match.group(0)
        if any(pattern.search(form_block) for pattern in csrf_evidence_res):
            continue

        findings.append(
            {
                "rule_id": "DJG.TPL.CSRF_TOKEN_MISSING",
                "file": rel,
                "line": text.count("\\n", 0, form_match.start()) + 1,
                "message": "POST form appears without CSRF protection",
                "severity": "medium",
            }
        )

print(json.dumps({"findings": findings}))
"""
        return [sys.executable, "-c", script, str(project_path)]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files) -> list[str]:
        _ = files
        return self.build_command(project_path)
