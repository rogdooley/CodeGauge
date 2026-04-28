from __future__ import annotations

import sys
from pathlib import Path

from .base import Scanner


class DjangoOrmHealthScanner(Scanner):
    scanner_name = "django_orm_health"
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
sources = list(root.rglob("*.py"))
findings = []
raw_sql_re = re.compile(r"\\.raw\\(")
select_related_re = re.compile(r"select_related\\(")
prefetch_related_re = re.compile(r"prefetch_related\\(")
queryset_iter_re = re.compile(r"\\.all\\(\\)")

for path in sources[:2000]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    rel = path.relative_to(root).as_posix()
    raw_sql_match = raw_sql_re.search(text)
    if raw_sql_match:
        findings.append(
            {
                "rule_id": "DJG.ORM.RAW_SQL_USAGE",
                "file": rel,
                "line": text.count("\\n", 0, raw_sql_match.start()) + 1,
                "message": "Raw SQL usage detected; verify parameterization",
                "severity": "medium",
            }
        )
    if queryset_iter_re.search(text) and not (select_related_re.search(text) or prefetch_related_re.search(text)):
        line = 1
        m = queryset_iter_re.search(text)
        if m:
            line = text.count("\\n", 0, m.start()) + 1
        findings.append(
            {
                "rule_id": "DJG.ORM.RELATED_FETCH_MISSING",
                "file": rel,
                "line": line,
                "message": "QuerySet iteration without select_related/prefetch_related",
                "severity": "low",
            }
        )

print(json.dumps({"findings": findings}))
"""
        return [sys.executable, "-c", script, str(project_path)]
