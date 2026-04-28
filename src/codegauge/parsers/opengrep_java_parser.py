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
class JavaRuleMapping:
    default_severity: Severity
    default_category: Category
    severity_prefixes: dict[str, Severity]
    category_prefixes: dict[str, Category]
    posture_prefixes: dict[str, str]


def _select_by_prefix(rule_id: str, mapping: Mapping[str, Any], default: Any) -> Any:
    for prefix in sorted(mapping.keys(), key=len, reverse=True):
        if rule_id.upper().startswith(prefix.upper()):
            return mapping[prefix]
    return default


def load_spring_rule_mapping(path: Path | None = None) -> JavaRuleMapping:
    if path is None:
        rule_file = resources.files("codegauge.mappings").joinpath("spring_rules.toml")
        payload = tomllib.loads(rule_file.read_text())
    else:
        payload = tomllib.loads(path.read_text())
    defaults = payload.get("defaults", {})
    severity_default = Severity(str(defaults.get("severity", "medium")).lower())
    category_default = Category(str(defaults.get("category", "maintainability")).lower())
    severity_map_raw = payload.get("severity_prefixes", {})
    category_map_raw = payload.get("category_prefixes", {})
    posture_map_raw = payload.get("posture_prefixes", {})

    return JavaRuleMapping(
        default_severity=severity_default,
        default_category=category_default,
        severity_prefixes={str(k).upper(): Severity(str(v).lower()) for k, v in severity_map_raw.items()},
        category_prefixes={str(k).upper(): Category(str(v).lower()) for k, v in category_map_raw.items()},
        posture_prefixes={str(k).upper(): str(v) for k, v in posture_map_raw.items()},
    )


class OpenGrepJavaParser(ScannerParser):
    parser_name = "opengrep_java_parser"
    supported_scanners = ("opengrep_java",)

    def __init__(self, mapping: JavaRuleMapping | None = None) -> None:
        self.mapping = mapping or load_spring_rule_mapping()

    def _map_severity(self, rule_id: str) -> Severity:
        return _select_by_prefix(rule_id, self.mapping.severity_prefixes, self.mapping.default_severity)

    def _map_category(self, rule_id: str) -> Category:
        return _select_by_prefix(rule_id, self.mapping.category_prefixes, self.mapping.default_category)

    def _map_posture(self, rule_id: str) -> str | None:
        return _select_by_prefix(rule_id, self.mapping.posture_prefixes, None)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        runs = parse_sarif_runs(stdout, scanner_name="opengrep_java")
        findings: list[Finding] = []
        for run in runs:
            results = require_list(run.get("results") or [], context="opengrep java sarif results")
            for result_obj in results:
                result = require_object(result_obj, context="opengrep java result")
                rule_id = require_string(result.get("ruleId") or "OPENGREP_JAVA", context="opengrep java ruleId")
                message_obj = require_object(result.get("message") or {}, context="opengrep java message")
                message = require_string(
                    message_obj.get("text") or result.get("message", {}).get("markdown") or "",
                    context="opengrep java message text",
                )
                locations = require_list(result.get("locations") or [], context="opengrep java locations")
                if not locations:
                    raise ScannerOutputInvalidError("opengrep java result must include at least one location")
                location = require_object(locations[0], context="opengrep java location")
                physical = require_object(location.get("physicalLocation"), context="opengrep java physicalLocation")
                artifact = require_object(physical.get("artifactLocation"), context="opengrep java artifactLocation")
                uri = require_string(artifact.get("uri"), context="opengrep java uri")
                region = require_object(physical.get("region") or {}, context="opengrep java region")
                line = region.get("startLine")
                column = region.get("startColumn")
                if line is not None and not isinstance(line, int):
                    raise ScannerOutputInvalidError("opengrep java startLine must be integer")
                if column is not None and not isinstance(column, int):
                    raise ScannerOutputInvalidError("opengrep java startColumn must be integer")
                raw_payload = dict(result)
                posture = self._map_posture(rule_id)
                if posture:
                    raw_payload["spring_posture"] = posture
                normalized = normalize_finding_path(uri, project_path, raw_payload=raw_payload)
                tags = [posture] if posture else []
                findings.append(
                    Finding(
                        tool="opengrep_java",
                        rule_id=rule_id,
                        severity=self._map_severity(rule_id),
                        category=self._map_category(rule_id),
                        language=Language.java,
                        file=normalized,
                        line=line,
                        column=column,
                        message=message,
                        tags=tags,
                        raw_payload=raw_payload,
                    )
                )
        return findings

