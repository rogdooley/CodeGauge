from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerOutputInvalidError, ScannerParser, normalize_finding_path
from .formats.json_parser import parse_json_document, require_list, require_object, require_string


class BanditParser(ScannerParser):
    parser_name = "bandit_parser"
    supported_scanners = ("bandit",)

    def _map_severity(self, value: str | None) -> Severity:
        normalized = (value or "").strip().upper()
        if normalized == "HIGH":
            return Severity.high
        if normalized == "LOW":
            return Severity.low
        return Severity.medium

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        payload = parse_json_document(stdout, scanner_name="bandit")
        root = require_object(payload, context="bandit payload")
        results = require_list(root.get("results"), context="bandit results")

        findings: list[Finding] = []
        for item in results:
            entry = require_object(item, context="bandit finding")
            filename = require_string(entry.get("filename"), context="bandit finding filename")
            rule_id = require_string(entry.get("test_id"), context="bandit finding test_id")
            message = require_string(entry.get("issue_text"), context="bandit finding issue_text")

            line_number = entry.get("line_number")
            if line_number is not None and not isinstance(line_number, int):
                raise ScannerOutputInvalidError("bandit finding line_number must be an integer")
            normalized_path = normalize_finding_path(filename, project_path, raw_payload=entry)

            findings.append(
                Finding(
                    tool="bandit",
                    rule_id=rule_id,
                    severity=self._map_severity(entry.get("issue_severity")),
                    category=Category.security,
                    language=Language.python,
                    file=normalized_path,
                    line=line_number,
                    column=None,
                    message=message,
                    raw_payload=entry,
                )
            )
        return findings
