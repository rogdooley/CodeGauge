from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerOutputInvalidError, ScannerParser, normalize_finding_path
from .formats.json_parser import parse_json_document, require_list, require_object, require_string


class PyrightParser(ScannerParser):
    parser_name = "pyright_parser"
    supported_scanners = ("pyright",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        payload = parse_json_document(stdout, scanner_name="pyright")
        root = require_object(payload, context="pyright payload")
        diagnostics = require_list(root.get("generalDiagnostics"), context="pyright generalDiagnostics")

        findings: list[Finding] = []
        for item in diagnostics:
            entry = require_object(item, context="pyright diagnostic")
            raw_file = require_string(entry.get("file"), context="pyright diagnostic file")
            message = require_string(entry.get("message"), context="pyright diagnostic message")
            severity_raw = require_string(entry.get("severity"), context="pyright diagnostic severity")

            rule = entry.get("rule")
            rule_id = str(rule) if rule is not None else "pyright"
            range_obj = require_object(entry.get("range"), context="pyright diagnostic range")
            start = require_object(range_obj.get("start"), context="pyright diagnostic range.start")
            line = start.get("line")
            character = start.get("character")
            if line is not None and not isinstance(line, int):
                raise ScannerOutputInvalidError("pyright diagnostic line must be an integer")
            if character is not None and not isinstance(character, int):
                raise ScannerOutputInvalidError("pyright diagnostic character must be an integer")

            normalized_path = normalize_finding_path(raw_file, project_path, raw_payload=entry)
            findings.append(
                Finding(
                    tool="pyright",
                    rule_id=rule_id,
                    severity=self._map_severity(severity_raw),
                    category=self._map_category(rule_id),
                    language=Language.python,
                    file=normalized_path,
                    line=(line + 1) if isinstance(line, int) else None,
                    column=(character + 1) if isinstance(character, int) else None,
                    message=message,
                    raw_payload=entry,
                )
            )
        return findings

    @staticmethod
    def _map_severity(value: str) -> Severity:
        normalized = value.strip().lower()
        if normalized == "error":
            return Severity.high
        if normalized == "warning":
            return Severity.medium
        if normalized in {"information", "info"}:
            return Severity.info
        return Severity.low

    @staticmethod
    def _map_category(rule_id: str) -> Category:
        lowered = rule_id.lower()
        if "import" in lowered:
            return Category.typing
        if "unused" in lowered:
            return Category.dead_code
        return Category.typing
