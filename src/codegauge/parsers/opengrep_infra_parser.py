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
class OpenGrepInfraRuleMapping:
    default_severity: Severity
    default_category: Category
    severity_prefixes: dict[str, Severity]
    category_prefixes: dict[str, Category]


def _select_by_prefix(rule_id: str, mapping: Mapping[str, Any], default: Any) -> Any:
    for prefix in sorted(mapping.keys(), key=len, reverse=True):
        if rule_id.upper().startswith(prefix.upper()):
            return mapping[prefix]
    return default


def load_opengrep_infra_rule_mapping(path: Path | None = None) -> OpenGrepInfraRuleMapping:
    if path is None:
        rule_file = resources.files("codegauge.mappings").joinpath("opengrep_infra_rules.toml")
        payload = tomllib.loads(rule_file.read_text())
    else:
        payload = tomllib.loads(path.read_text())
    defaults = payload.get("defaults", {})
    severity_default = Severity(str(defaults.get("severity", "medium")).lower())
    category_default = Category(str(defaults.get("category", "security")).lower())
    return OpenGrepInfraRuleMapping(
        default_severity=severity_default,
        default_category=category_default,
        severity_prefixes={str(k).upper(): Severity(str(v).lower()) for k, v in payload.get("severity_prefixes", {}).items()},
        category_prefixes={str(k).upper(): Category(str(v).lower()) for k, v in payload.get("category_prefixes", {}).items()},
    )


class OpenGrepInfraParser(ScannerParser):
    parser_name = "opengrep_infra_parser"
    supported_scanners = ("opengrep_infra",)

    def __init__(self, mapping: OpenGrepInfraRuleMapping | None = None) -> None:
        self.mapping = mapping or load_opengrep_infra_rule_mapping()

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        runs = parse_sarif_runs(stdout, scanner_name="opengrep_infra")
        findings: list[Finding] = []
        for run in runs:
            results = require_list(run.get("results") or [], context="opengrep infra results")
            for result_obj in results:
                result = require_object(result_obj, context="opengrep infra result")
                rule_id = require_string(result.get("ruleId") or "INF.UNKNOWN", context="opengrep infra ruleId")
                message_obj = require_object(result.get("message") or {}, context="opengrep infra message")
                message = require_string(message_obj.get("text") or "", context="opengrep infra message text")
                locations = require_list(result.get("locations") or [], context="opengrep infra locations")
                if not locations:
                    raise ScannerOutputInvalidError("opengrep infra result must include at least one location")
                location = require_object(locations[0], context="opengrep infra location")
                physical = require_object(location.get("physicalLocation"), context="opengrep infra physicalLocation")
                artifact = require_object(physical.get("artifactLocation"), context="opengrep infra artifactLocation")
                uri = require_string(artifact.get("uri"), context="opengrep infra uri")
                region = require_object(physical.get("region") or {}, context="opengrep infra region")
                line = region.get("startLine")
                column = region.get("startColumn")
                if line is not None and not isinstance(line, int):
                    raise ScannerOutputInvalidError("opengrep infra startLine must be integer")
                if column is not None and not isinstance(column, int):
                    raise ScannerOutputInvalidError("opengrep infra startColumn must be integer")
                raw_payload = dict(result)
                normalized = normalize_finding_path(uri, project_path, raw_payload=raw_payload)
                findings.append(
                    Finding(
                        tool="opengrep_infra",
                        rule_id=rule_id,
                        severity=_select_by_prefix(rule_id, self.mapping.severity_prefixes, self.mapping.default_severity),
                        category=_select_by_prefix(rule_id, self.mapping.category_prefixes, self.mapping.default_category),
                        language=Language.general,
                        file=normalized,
                        line=line,
                        column=column,
                        message=message,
                        raw_payload=raw_payload,
                    )
                )
        return findings
