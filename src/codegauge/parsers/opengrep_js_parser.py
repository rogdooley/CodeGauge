from __future__ import annotations

import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerOutputInvalidError, ScannerParser, normalize_finding_path
from .formats import parse_sarif_runs, require_list, require_object, require_string


@dataclass(frozen=True)
class OpenGrepJSRuleMapping:
    default_severity: Severity
    default_category: Category
    severity_prefixes: dict[str, Severity]
    category_prefixes: dict[str, Category]


def _select_by_prefix(rule_id: str, mapping: Mapping[str, Any], default: Any) -> Any:
    for prefix in sorted(mapping.keys(), key=len, reverse=True):
        if rule_id.upper().startswith(prefix.upper()):
            return mapping[prefix]
    return default


def load_opengrep_js_rule_mapping(path: Path | None = None) -> OpenGrepJSRuleMapping:
    if path is None:
        rule_file = resources.files("codegauge.mappings").joinpath("opengrep_js_rules.toml")
        payload = tomllib.loads(rule_file.read_text())
    else:
        payload = tomllib.loads(path.read_text())

    defaults = payload.get("defaults", {})
    severity_default = Severity(str(defaults.get("severity", "medium")).lower())
    category_default = Category(str(defaults.get("category", "lint")).lower())
    severity_prefixes = {str(k).upper(): Severity(str(v).lower()) for k, v in payload.get("severity_prefixes", {}).items()}
    category_prefixes = {str(k).upper(): Category(str(v).lower()) for k, v in payload.get("category_prefixes", {}).items()}
    return OpenGrepJSRuleMapping(
        default_severity=severity_default,
        default_category=category_default,
        severity_prefixes=severity_prefixes,
        category_prefixes=category_prefixes,
    )


class OpenGrepJSParser(ScannerParser):
    parser_name = "opengrep_js_parser"
    supported_scanners = ("opengrep_js",)

    def __init__(self, mapping: OpenGrepJSRuleMapping | None = None) -> None:
        self.mapping = mapping or load_opengrep_js_rule_mapping()

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        runs = parse_sarif_runs(stdout, scanner_name="opengrep_js")
        findings: list[Finding] = []
        for run in runs:
            results = require_list(run.get("results") or [], context="opengrep js sarif results")
            for result_obj in results:
                result = require_object(result_obj, context="opengrep js result")
                rule_id = require_string(result.get("ruleId") or "OPENGREP_JS", context="opengrep js ruleId")
                message_obj = require_object(result.get("message") or {}, context="opengrep js message")
                message = require_string(
                    message_obj.get("text") or result.get("message", {}).get("markdown") or "",
                    context="opengrep js message text",
                )
                locations = require_list(result.get("locations") or [], context="opengrep js locations")
                if not locations:
                    raise ScannerOutputInvalidError("opengrep js result must include at least one location")
                location = require_object(locations[0], context="opengrep js location")
                physical = require_object(location.get("physicalLocation"), context="opengrep js physicalLocation")
                artifact = require_object(physical.get("artifactLocation"), context="opengrep js artifactLocation")
                uri = require_string(artifact.get("uri"), context="opengrep js uri")
                region = require_object(physical.get("region") or {}, context="opengrep js region")
                line = region.get("startLine")
                column = region.get("startColumn")
                if line is not None and not isinstance(line, int):
                    raise ScannerOutputInvalidError("opengrep js startLine must be integer")
                if column is not None and not isinstance(column, int):
                    raise ScannerOutputInvalidError("opengrep js startColumn must be integer")
                raw_payload = dict(result)
                normalized = normalize_finding_path(uri, project_path, raw_payload=raw_payload)
                findings.append(
                    Finding(
                        tool="opengrep_js",
                        rule_id=rule_id,
                        severity=self._map_severity(rule_id),
                        category=self._map_category(rule_id),
                        language=self._map_language(normalized),
                        file=normalized,
                        line=line,
                        column=column,
                        message=message,
                        raw_payload=raw_payload,
                    )
                )
        return findings

    def _map_severity(self, rule_id: str) -> Severity:
        return _select_by_prefix(rule_id, self.mapping.severity_prefixes, self.mapping.default_severity)

    def _map_category(self, rule_id: str) -> Category:
        return _select_by_prefix(rule_id, self.mapping.category_prefixes, self.mapping.default_category)

    @staticmethod
    def _map_language(path: Path) -> Language:
        suffix = path.suffix.lower()
        if suffix in {".ts", ".tsx"}:
            return Language.typescript
        return Language.javascript
