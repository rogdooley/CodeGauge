from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerParser, normalize_finding_path
from .formats import parse_xml_document


class SpotBugsParser(ScannerParser):
    parser_name = "spotbugs_parser"
    supported_scanners = ("spotbugs",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        root = parse_xml_document(stdout, scanner_name="spotbugs")
        findings: list[Finding] = []
        for bug in root.findall(".//BugInstance"):
            rank_value = bug.attrib.get("rank")
            rule_id = bug.attrib.get("type") or "SPOTBUGS"
            category = Category.security if "SECURITY" in rule_id.upper() else Category.maintainability
            severity = self._severity_from_rank(rank_value)
            message_node = bug.find(".//LongMessage")
            message = (message_node.text or "").strip() if message_node is not None and message_node.text else rule_id

            source_line = bug.find(".//SourceLine")
            if source_line is None:
                continue
            source_path = source_line.attrib.get("sourcepath") or source_line.attrib.get("sourcefile")
            if not source_path:
                continue
            start_line = source_line.attrib.get("start")
            line = int(start_line) if start_line and start_line.isdigit() else None
            raw_payload = {
                "type": rule_id,
                "rank": rank_value,
            }
            normalized_path = normalize_finding_path(source_path, project_path, raw_payload=raw_payload)
            findings.append(
                Finding(
                    tool="spotbugs",
                    rule_id=rule_id,
                    severity=severity,
                    category=category,
                    language=Language.java,
                    file=normalized_path,
                    line=line,
                    column=None,
                    message=message,
                    raw_payload=raw_payload,
                )
            )
        return findings

    @staticmethod
    def _severity_from_rank(rank: str | None) -> Severity:
        if rank is None:
            return Severity.medium
        try:
            value = int(rank)
        except ValueError:
            return Severity.medium
        if value <= 4:
            return Severity.high
        if value <= 9:
            return Severity.medium
        return Severity.low

