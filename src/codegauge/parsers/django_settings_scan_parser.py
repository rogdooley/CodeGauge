from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerOutputInvalidError, ScannerParser, normalize_finding_path
from .formats import parse_json_document, require_list, require_object, require_string


class DjangoSettingsScanParser(ScannerParser):
    parser_name = "django_settings_scan_parser"
    supported_scanners = ("django_settings_scan",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        payload = parse_json_document(stdout or "{}", scanner_name="django_settings_scan")
        root = require_object(payload, context="django settings payload")
        entries = require_list(root.get("findings") or [], context="django settings findings")

        findings: list[Finding] = []
        for item in entries:
            entry = require_object(item, context="django settings finding")
            rule_id = require_string(entry.get("rule_id"), context="django settings rule_id")
            file_value = require_string(entry.get("file"), context="django settings file")
            message = require_string(entry.get("message"), context="django settings message")
            line = entry.get("line")
            if line is not None and not isinstance(line, int):
                raise ScannerOutputInvalidError("django settings line must be integer")
            normalized = normalize_finding_path(file_value, project_path, raw_payload=entry)
            findings.append(
                Finding(
                    tool="django_settings_scan",
                    rule_id=rule_id,
                    severity=self._severity(entry.get("severity")),
                    category=Category.security,
                    language=Language.python,
                    file=normalized,
                    line=line,
                    message=message,
                    raw_payload=entry,
                )
            )
        return findings

    @staticmethod
    def _severity(value: object) -> Severity:
        text = str(value or "").lower()
        if text == "high":
            return Severity.high
        if text == "low":
            return Severity.low
        return Severity.medium
