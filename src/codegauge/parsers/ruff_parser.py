from __future__ import annotations

import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerOutputInvalidError, ScannerParser, normalize_finding_path
from .formats.json_parser import parse_json_document, require_list, require_object, require_string


@dataclass(frozen=True)
class RuffRuleMapping:
    default_severity: Severity
    default_category: Category
    severity_prefixes: dict[str, Severity]
    category_prefixes: dict[str, Category]


def _select_by_prefix(rule_id: str, mapping: Mapping[str, Any], default: Any) -> Any:
    for prefix in sorted(mapping.keys(), key=len, reverse=True):
        if rule_id.upper().startswith(prefix.upper()):
            return mapping[prefix]
    return default


def load_ruff_rule_mapping(path: Path | None = None) -> RuffRuleMapping:
    if path is None:
        rule_file = resources.files("codegauge.mappings").joinpath("ruff_rules.toml")
        payload = tomllib.loads(rule_file.read_text())
    else:
        payload = tomllib.loads(path.read_text())

    defaults = payload.get("defaults", {})
    severity_default_raw = defaults.get("severity", "medium")
    category_default_raw = defaults.get("category", "lint")
    severity_map_raw = payload.get("severity_prefixes", {})
    category_map_raw = payload.get("category_prefixes", {})

    severity_default = Severity(str(severity_default_raw).lower())
    category_default = Category(str(category_default_raw).lower())
    severity_prefixes = {str(k).upper(): Severity(str(v).lower()) for k, v in severity_map_raw.items()}
    category_prefixes = {str(k).upper(): Category(str(v).lower()) for k, v in category_map_raw.items()}
    return RuffRuleMapping(
        default_severity=severity_default,
        default_category=category_default,
        severity_prefixes=severity_prefixes,
        category_prefixes=category_prefixes,
    )


class RuffParser(ScannerParser):
    parser_name = "ruff_parser"
    supported_scanners = ("ruff",)

    def __init__(self, mapping: RuffRuleMapping | None = None) -> None:
        self.mapping = mapping or load_ruff_rule_mapping()

    def _map_severity(self, rule_id: str) -> Severity:
        return _select_by_prefix(rule_id, self.mapping.severity_prefixes, self.mapping.default_severity)

    def _map_category(self, rule_id: str) -> Category:
        return _select_by_prefix(rule_id, self.mapping.category_prefixes, self.mapping.default_category)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        parsed = parse_json_document(stdout, scanner_name="ruff")
        entries = require_list(parsed, context="ruff JSON output")

        findings: list[Finding] = []
        for item in entries:
            entry = require_object(item, context="ruff finding entry")
            location = require_object(entry.get("location"), context="ruff location")
            filename = require_string(entry.get("filename"), context="ruff finding filename")
            code = require_string(entry.get("code"), context="ruff finding code")
            message = require_string(entry.get("message"), context="ruff finding message")
            row = location.get("row")
            column = location.get("column")
            if row is not None and not isinstance(row, int):
                raise ScannerOutputInvalidError("ruff finding row must be an integer")
            if column is not None and not isinstance(column, int):
                raise ScannerOutputInvalidError("ruff finding column must be an integer")
            normalized_path = normalize_finding_path(filename, project_path, raw_payload=entry)

            findings.append(
                Finding(
                    tool="ruff",
                    rule_id=code,
                    severity=self._map_severity(code),
                    category=self._map_category(code),
                    language=Language.python,
                    file=normalized_path,
                    line=row,
                    column=column,
                    message=message,
                    raw_payload=entry,
                )
            )
        return findings
