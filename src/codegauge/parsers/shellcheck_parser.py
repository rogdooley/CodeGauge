from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerOutputInvalidError, ScannerParser, normalize_finding_path
from .formats import parse_json_document, require_list, require_object, require_string


class ShellCheckParser(ScannerParser):
    parser_name = "shellcheck_parser"
    supported_scanners = ("shellcheck",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        payload = parse_json_document(stdout, scanner_name="shellcheck")
        entries = require_list(payload, context="shellcheck payload")
        findings: list[Finding] = []
        for item in entries:
            entry = require_object(item, context="shellcheck finding")
            rule_code = entry.get("code")
            file_value = require_string(entry.get("file"), context="shellcheck file")
            message = require_string(entry.get("message"), context="shellcheck message")
            line = entry.get("line")
            if line is not None and not isinstance(line, int):
                raise ScannerOutputInvalidError("shellcheck line must be integer")
            normalized = normalize_finding_path(file_value, project_path, raw_payload=entry)
            rule_id = f"SHELLCHECK.SC{int(rule_code)}" if isinstance(rule_code, int) else "SHELLCHECK.UNKNOWN"
            level = str(entry.get("level") or "style").lower()
            findings.append(
                Finding(
                    tool="shellcheck",
                    rule_id=rule_id,
                    severity=self._severity(level),
                    category=Category.lint,
                    language=Language.general,
                    file=normalized,
                    line=line,
                    message=message,
                    raw_payload=entry,
                )
            )
        return findings

    @staticmethod
    def _severity(level: str) -> Severity:
        if level in {"error"}:
            return Severity.high
        if level in {"warning"}:
            return Severity.medium
        if level in {"info"}:
            return Severity.low
        return Severity.info
