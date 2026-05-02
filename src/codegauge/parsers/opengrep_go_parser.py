from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerOutputInvalidError, ScannerParser, normalize_finding_path
from .formats import parse_sarif_runs, require_list, require_object, require_string


class OpenGrepGoParser(ScannerParser):
    parser_name = "opengrep_go_parser"
    supported_scanners = ("opengrep_go",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        runs = parse_sarif_runs(stdout, scanner_name="opengrep_go")
        findings: list[Finding] = []
        for run in runs:
            results = require_list(run.get("results") or [], context="opengrep go results")
            for raw in results:
                result = require_object(raw, context="opengrep go result")
                rule_id = require_string(result.get("ruleId") or "OPENGREP_GO", context="opengrep go ruleId")
                message_obj = require_object(result.get("message") or {}, context="opengrep go message")
                message = require_string(message_obj.get("text") or "OpenGrep Go finding", context="opengrep go text")
                locations = require_list(result.get("locations") or [], context="opengrep go locations")
                if not locations:
                    raise ScannerOutputInvalidError("opengrep go result must include at least one location")
                location = require_object(locations[0], context="opengrep go location")
                physical = require_object(location.get("physicalLocation"), context="opengrep go physicalLocation")
                artifact = require_object(physical.get("artifactLocation"), context="opengrep go artifactLocation")
                uri = require_string(artifact.get("uri"), context="opengrep go uri")
                region = require_object(physical.get("region") or {}, context="opengrep go region")
                line = region.get("startLine")
                column = region.get("startColumn")
                normalized = normalize_finding_path(uri, project_path, raw_payload=result)
                findings.append(
                    Finding(
                        tool="opengrep_go",
                        rule_id=rule_id,
                        severity=Severity.medium,
                        category=Category.maintainability,
                        language=Language.go,
                        file=normalized,
                        line=int(line) if isinstance(line, int) else None,
                        column=int(column) if isinstance(column, int) else None,
                        message=message,
                        raw_payload=result,
                    )
                )
        return findings
