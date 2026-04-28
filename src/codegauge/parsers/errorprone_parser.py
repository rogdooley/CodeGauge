from __future__ import annotations

from pathlib import Path
import re
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerOutputInvalidError, ScannerParser, normalize_finding_path
from .formats import parse_json_document, require_list, require_object, require_string


class ErrorProneParser(ScannerParser):
    parser_name = "errorprone_parser"
    supported_scanners = ("errorprone",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if stdout.strip():
            if stdout.lstrip().startswith("["):
                return self._parse_json(stdout, project_path)
        if stderr.strip():
            return self._parse_text(stderr, project_path)
        if not stdout.strip():
            return []
        return self._parse_text(stdout, project_path)

    def _parse_json(self, stdout: str, project_path: Path) -> Sequence[Finding]:
        payload = parse_json_document(stdout, scanner_name="errorprone")
        diagnostics = require_list(payload, context="errorprone diagnostics")
        findings: list[Finding] = []
        for item in diagnostics:
            diagnostic = require_object(item, context="errorprone diagnostic")
            file_name = require_string(diagnostic.get("file"), context="errorprone file")
            rule_id = require_string(diagnostic.get("checkName") or "ERROR_PRONE", context="errorprone checkName")
            message = require_string(diagnostic.get("message"), context="errorprone message")
            line = diagnostic.get("line")
            column = diagnostic.get("column")
            if line is not None and not isinstance(line, int):
                raise ScannerOutputInvalidError("errorprone line must be integer")
            if column is not None and not isinstance(column, int):
                raise ScannerOutputInvalidError("errorprone column must be integer")
            raw_payload = dict(diagnostic)
            normalized_path = normalize_finding_path(file_name, project_path, raw_payload=raw_payload)
            findings.append(
                Finding(
                    tool="errorprone",
                    rule_id=rule_id,
                    severity=self._severity(diagnostic.get("severity")),
                    category=self._category(rule_id),
                    language=Language.java,
                    file=normalized_path,
                    line=line,
                    column=column,
                    message=message,
                    raw_payload=raw_payload,
                )
            )
        return findings

    def _parse_text(self, text: str, project_path: Path) -> Sequence[Finding]:
        findings: list[Finding] = []
        pattern = re.compile(
            r"(?P<file>[^\s:]+\.java):(?P<line>\d+):\s*(?P<severity>warning|error):\s*(?P<message>.+?)(?:\s+\[(?P<rule>[^\]]+)\])?$",
            re.IGNORECASE,
        )
        for line in text.splitlines():
            match = pattern.search(line.strip())
            if not match:
                continue
            file_name = match.group("file")
            line_no = int(match.group("line"))
            severity = self._severity(match.group("severity"))
            message = match.group("message").strip()
            rule_id = (match.group("rule") or "ERROR_PRONE").strip()
            raw_payload = {"raw_line": line}
            normalized_path = normalize_finding_path(file_name, project_path, raw_payload=raw_payload)
            findings.append(
                Finding(
                    tool="errorprone",
                    rule_id=rule_id,
                    severity=severity,
                    category=self._category(rule_id),
                    language=Language.java,
                    file=normalized_path,
                    line=line_no,
                    column=None,
                    message=message,
                    raw_payload=raw_payload,
                )
            )
        return findings

    @staticmethod
    def _severity(value: str | None) -> Severity:
        normalized = (value or "").strip().upper()
        if normalized in {"ERROR"}:
            return Severity.high
        if normalized in {"WARNING"}:
            return Severity.medium
        return Severity.info

    @staticmethod
    def _category(rule_id: str) -> Category:
        lowered = rule_id.lower()
        if "null" in lowered or "injection" in lowered:
            return Category.security
        if "unused" in lowered:
            return Category.dead_code
        return Category.maintainability
