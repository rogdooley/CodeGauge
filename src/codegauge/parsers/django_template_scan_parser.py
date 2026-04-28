from __future__ import annotations

from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerOutputInvalidError, ScannerParser, normalize_finding_path
from .formats import parse_json_document, require_list, require_object, require_string


class DjangoTemplateScanParser(ScannerParser):
    parser_name = "django_template_scan_parser"
    supported_scanners = ("django_template_scan",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        payload = parse_json_document(stdout or "{}", scanner_name="django_template_scan")
        root = require_object(payload, context="django template payload")
        entries = require_list(root.get("findings") or [], context="django template findings")

        findings: list[Finding] = []
        for item in entries:
            entry = require_object(item, context="django template finding")
            rule_id = require_string(entry.get("rule_id"), context="django template rule_id")
            file_value = require_string(entry.get("file"), context="django template file")
            message = require_string(entry.get("message"), context="django template message")
            line = entry.get("line")
            if line is not None and not isinstance(line, int):
                raise ScannerOutputInvalidError("django template line must be integer")
            normalized = normalize_finding_path(file_value, project_path, raw_payload=entry)
            findings.append(
                Finding(
                    tool="django_template_scan",
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
