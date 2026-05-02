from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerParser


class GovulncheckParser(ScannerParser):
    parser_name = "govulncheck_parser"
    supported_scanners = ("govulncheck",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        del stderr, project_path
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
            vuln = payload.get("vuln") if isinstance(payload.get("vuln"), dict) else None
            if vuln is None:
                continue
            osv = str(vuln.get("osv") or "")
            summary = str(vuln.get("summary") or "Go vulnerability detected")
            findings.append(
                Finding(
                    tool="govulncheck",
                    rule_id=f"GOVULNCHECK.{(osv or 'UNKNOWN').upper()}",
                    severity=Severity.high,
                    category=Category.security,
                    language=Language.go,
                    file=Path("go.mod"),
                    line=1,
                    message=summary,
                    raw_payload=payload,
                )
            )
        return findings
