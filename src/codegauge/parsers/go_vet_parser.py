from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerParser, normalize_finding_path


class GoVetParser(ScannerParser):
    parser_name = "go_vet_parser"
    supported_scanners = ("go_vet",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        combined = "\n".join(part for part in (stdout, stderr) if part)
        findings: list[Finding] = []
        for raw in combined.splitlines():
            line = raw.strip()
            if not line or ":" not in line:
                continue
            parts = line.split(":", 3)
            if len(parts) < 4:
                continue
            file_raw, line_raw, column_raw, message = parts[0], parts[1], parts[2], parts[3].strip()
            if not file_raw.endswith(".go"):
                continue
            try:
                line_num = int(line_raw)
            except ValueError:
                line_num = 1
            try:
                column_num = int(column_raw)
            except ValueError:
                column_num = 1
            normalized = normalize_finding_path(file_raw, project_path)
            findings.append(
                Finding(
                    tool="go_vet",
                    rule_id="GO.VET",
                    severity=Severity.medium,
                    category=Category.maintainability,
                    language=Language.go,
                    file=normalized,
                    line=line_num,
                    column=column_num,
                    message=message,
                    raw_payload={"raw": line},
                )
            )
        return findings
