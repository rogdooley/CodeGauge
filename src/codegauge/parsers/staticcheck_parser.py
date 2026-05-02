from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerParser, normalize_finding_path


class StaticcheckParser(ScannerParser):
    parser_name = "staticcheck_parser"
    supported_scanners = ("staticcheck",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        del stderr
        findings: list[Finding] = []
        for raw in stdout.splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            location = payload.get("location") if isinstance(payload.get("location"), dict) else {}
            file_raw = str(location.get("file") or "")
            if not file_raw:
                continue
            normalized = normalize_finding_path(file_raw, project_path, raw_payload=payload)
            code = str(payload.get("code") or "STATICCHECK")
            message = str(payload.get("message") or "Staticcheck issue")
            findings.append(
                Finding(
                    tool="staticcheck",
                    rule_id=f"STATICCHECK.{code}",
                    severity=Severity.medium,
                    category=Category.maintainability,
                    language=Language.go,
                    file=normalized,
                    line=int(location.get("line") or 1),
                    column=int(location.get("column") or 1),
                    message=message,
                    raw_payload=payload,
                )
            )
        return findings
