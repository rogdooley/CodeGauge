from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerOutputInvalidError, ScannerParser, normalize_finding_path
from .formats import parse_json_document, parse_xml_document, require_list, require_object, require_string


class PMDParser(ScannerParser):
    parser_name = "pmd_parser"
    supported_scanners = ("pmd",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        if stdout.lstrip().startswith("<"):
            return self._parse_xml(stdout, project_path)
        payload = parse_json_document(stdout, scanner_name="pmd")
        if isinstance(payload, list):
            findings: list[Finding] = []
            for item in payload:
                if not isinstance(item, dict):
                    continue
                findings.extend(self._parse_json_payload(item, project_path))
            return findings
        if not isinstance(payload, dict):
            raise ScannerOutputInvalidError("pmd payload must be an object")
        return self._parse_json_payload(payload, project_path)

    def _parse_json_payload(self, payload: dict[str, Any], project_path: Path) -> Sequence[Finding]:
        root = require_object(payload, context="pmd payload")
        files = require_list(root.get("files") or [], context="pmd files")

        findings: list[Finding] = []
        for file_obj in files:
            file_entry = require_object(file_obj, context="pmd file entry")
            filename = require_string(file_entry.get("filename"), context="pmd filename")
            violations = require_list(file_entry.get("violations") or [], context="pmd violations")
            for violation_obj in violations:
                violation = require_object(violation_obj, context="pmd violation")
                rule_id = require_string(violation.get("rule"), context="pmd violation rule")
                message = require_string(violation.get("description"), context="pmd violation description")
                line = self._optional_int(violation.get("beginline"), context="pmd beginline")
                column = self._optional_int(violation.get("begincolumn"), context="pmd begincolumn")
                priority = self._optional_int(violation.get("priority"), context="pmd priority")
                severity = self._severity_from_priority(priority)
                category = self._category_for_rule(rule_id)
                raw_payload = dict(violation)
                normalized_path = normalize_finding_path(filename, project_path, raw_payload=raw_payload)
                findings.append(
                    Finding(
                        tool="pmd",
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

    def parse_metadata(self, stdout: str, stderr: str, project_path: Path) -> dict[str, Any]:
        if not stdout.strip():
            return {}
        if stdout.lstrip().startswith("<"):
            return {}
        payload = parse_json_document(stdout, scanner_name="pmd")
        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                parsed = self._parse_metadata_payload(item)
                if parsed:
                    return parsed
            return {}
        if not isinstance(payload, dict):
            return {}
        return self._parse_metadata_payload(payload)

    def _parse_metadata_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        root = require_object(payload, context="pmd payload")
        duplication = root.get("duplication") or root.get("cpd")
        if not isinstance(duplication, dict):
            return {}
        value = duplication.get("percentDuplicatedLines") or duplication.get("duplication_percent")
        if isinstance(value, (int, float)):
            return {"scalar_metrics": {"duplication_percent": float(value)}}
        return {}

    @staticmethod
    def _optional_int(value: Any, *, context: str) -> int | None:
        if value is None:
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
        raise ScannerOutputInvalidError(f"{context} must be an integer")

    @staticmethod
    def _severity_from_priority(priority: int | None) -> Severity:
        if priority is None:
            return Severity.medium
        if priority <= 2:
            return Severity.high
        if priority <= 3:
            return Severity.medium
        return Severity.low

    @staticmethod
    def _category_for_rule(rule_id: str) -> Category:
        lowered = rule_id.lower()
        if "security" in lowered:
            return Category.security
        if "unused" in lowered:
            return Category.dead_code
        if "cyclo" in lowered or "complexity" in lowered:
            return Category.complexity
        if "design" in lowered or "simplify" in lowered:
            return Category.maintainability
        return Category.lint

    def _parse_xml(self, stdout: str, project_path: Path) -> Sequence[Finding]:
        root = parse_xml_document(stdout, scanner_name="pmd")
        findings: list[Finding] = []
        for file_node in root.findall(".//file"):
            filename = file_node.attrib.get("name")
            if not filename:
                continue
            for violation in file_node.findall("violation"):
                rule_id = violation.attrib.get("rule") or violation.attrib.get("ruleset") or "PMD"
                message = (violation.text or "").strip() or rule_id
                line = self._optional_int(violation.attrib.get("beginline"), context="pmd beginline")
                column = self._optional_int(violation.attrib.get("begincolumn"), context="pmd begincolumn")
                priority = self._optional_int(violation.attrib.get("priority"), context="pmd priority")
                severity = self._severity_from_priority(priority)
                category = self._category_for_rule(rule_id)
                raw_payload = dict(violation.attrib)
                normalized_path = normalize_finding_path(filename, project_path, raw_payload=raw_payload)
                findings.append(
                    Finding(
                        tool="pmd",
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
