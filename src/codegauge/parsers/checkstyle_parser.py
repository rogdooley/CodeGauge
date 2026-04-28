from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerParser, normalize_finding_path
from .formats import parse_xml_document


class CheckstyleParser(ScannerParser):
    parser_name = "checkstyle_parser"
    supported_scanners = ("checkstyle",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        root = parse_xml_document(stdout, scanner_name="checkstyle")
        findings: list[Finding] = []
        for file_node in root.findall(".//file"):
            file_name = file_node.attrib.get("name")
            if not file_name:
                continue
            for error in file_node.findall("error"):
                rule_id = error.attrib.get("source") or "CHECKSTYLE"
                message = error.attrib.get("message") or rule_id
                line_value = error.attrib.get("line")
                column_value = error.attrib.get("column")
                line = int(line_value) if line_value and line_value.isdigit() else None
                column = int(column_value) if column_value and column_value.isdigit() else None
                severity = self._severity(error.attrib.get("severity"))
                category = Category.lint
                if "imports" in rule_id.lower() or "unused" in rule_id.lower():
                    category = Category.dead_code
                raw_payload = dict(error.attrib)
                normalized_path = normalize_finding_path(file_name, project_path, raw_payload=raw_payload)
                findings.append(
                    Finding(
                        tool="checkstyle",
                        rule_id=rule_id,
                        severity=severity,
                        category=category,
                        language=Language.java,
                        file=normalized_path,
                        line=line,
                        column=column,
                        message=message,
                        raw_payload=raw_payload,
                    )
                )
        return findings

    @staticmethod
    def _severity(value: str | None) -> Severity:
        lowered = (value or "").strip().lower()
        if lowered in {"error"}:
            return Severity.medium
        if lowered in {"warning"}:
            return Severity.low
        if lowered in {"info", "ignore"}:
            return Severity.info
        return Severity.low

