from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerOutputInvalidError, ScannerParser, normalize_finding_path
from .formats import parse_sarif_runs, require_list, require_object, require_string


class OpenGrepPHPParser(ScannerParser):
    parser_name = "opengrep_php_parser"
    supported_scanners = ("opengrep_php",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        runs = parse_sarif_runs(stdout, scanner_name="opengrep_php")
        findings: list[Finding] = []
        for run in runs:
            results = require_list(run.get("results") or [], context="opengrep php results")
            for raw in results:
                result = require_object(raw, context="opengrep php result")
                rule_id = require_string(result.get("ruleId") or "OPENGREP_PHP", context="opengrep php ruleId")
                message_obj = require_object(result.get("message") or {}, context="opengrep php message")
                message = require_string(message_obj.get("text") or "OpenGrep PHP finding", context="opengrep php text")
                locations = require_list(result.get("locations") or [], context="opengrep php locations")
                if not locations:
                    raise ScannerOutputInvalidError("opengrep php result must include at least one location")
                location = require_object(locations[0], context="opengrep php location")
                physical = require_object(location.get("physicalLocation"), context="opengrep php physicalLocation")
                artifact = require_object(physical.get("artifactLocation"), context="opengrep php artifactLocation")
                uri = require_string(artifact.get("uri"), context="opengrep php uri")
                region = require_object(physical.get("region") or {}, context="opengrep php region")
                line = region.get("startLine")
                column = region.get("startColumn")
                normalized = normalize_finding_path(uri, project_path, raw_payload=result)
                findings.append(
                    Finding(
                        tool="opengrep_php",
                        rule_id=rule_id,
                        severity=self._severity(rule_id),
                        category=self._category(rule_id),
                        language=Language.php,
                        file=normalized,
                        line=int(line) if isinstance(line, int) else None,
                        column=int(column) if isinstance(column, int) else None,
                        message=message,
                        raw_payload=result,
                    )
                )
        return findings

    @staticmethod
    def _severity(rule_id: str) -> Severity:
        upper = rule_id.upper()
        if upper.startswith("SEC") or "SQL" in upper:
            return Severity.high
        if upper.startswith("STYLE"):
            return Severity.low
        return Severity.medium

    @staticmethod
    def _category(rule_id: str) -> Category:
        upper = rule_id.upper()
        if upper.startswith("SEC") or "XSS" in upper or "SQL" in upper:
            return Category.security
        if upper.startswith("DEAD"):
            return Category.dead_code
        return Category.maintainability
