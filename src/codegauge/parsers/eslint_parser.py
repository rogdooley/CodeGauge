from __future__ import annotations

import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerOutputInvalidError, ScannerParser, normalize_finding_path
from .formats import parse_json_document, require_list, require_object, require_string


@dataclass(frozen=True)
class ESLintRuleMapping:
    default_severity: Severity
    default_category: Category
    severity_prefixes: dict[str, Severity]
    category_prefixes: dict[str, Category]


def _select_by_prefix(rule_id: str, mapping: Mapping[str, Any], default: Any) -> Any:
    for prefix in sorted(mapping.keys(), key=len, reverse=True):
        if rule_id.upper().startswith(prefix.upper()):
            return mapping[prefix]
    return default


def load_eslint_rule_mapping(path: Path | None = None) -> ESLintRuleMapping:
    if path is None:
        rule_file = resources.files("codegauge.mappings").joinpath("eslint_rules.toml")
        payload = tomllib.loads(rule_file.read_text())
    else:
        payload = tomllib.loads(path.read_text())

    defaults = payload.get("defaults", {})
    severity_default = Severity(str(defaults.get("severity", "medium")).lower())
    category_default = Category(str(defaults.get("category", "lint")).lower())
    severity_prefixes = {str(k).upper(): Severity(str(v).lower()) for k, v in payload.get("severity_prefixes", {}).items()}
    category_prefixes = {str(k).upper(): Category(str(v).lower()) for k, v in payload.get("category_prefixes", {}).items()}
    return ESLintRuleMapping(
        default_severity=severity_default,
        default_category=category_default,
        severity_prefixes=severity_prefixes,
        category_prefixes=category_prefixes,
    )


class ESLintParser(ScannerParser):
    parser_name = "eslint_parser"
    supported_scanners = ("eslint",)

    def __init__(self, mapping: ESLintRuleMapping | None = None) -> None:
        self.mapping = mapping or load_eslint_rule_mapping()

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        payload = parse_json_document(stdout, scanner_name="eslint")
        entries = require_list(payload, context="eslint payload")
        findings: list[Finding] = []
        for file_entry_raw in entries:
            file_entry = require_object(file_entry_raw, context="eslint file entry")
            file_path = require_string(file_entry.get("filePath"), context="eslint filePath")
            messages = require_list(file_entry.get("messages") or [], context="eslint messages")
            for message_raw in messages:
                message_entry = require_object(message_raw, context="eslint message")
                rule_id = str(message_entry.get("ruleId") or "ESLINT.UNKNOWN")
                message = require_string(message_entry.get("message"), context="eslint message text")
                line = message_entry.get("line")
                column = message_entry.get("column")
                if line is not None and not isinstance(line, int):
                    raise ScannerOutputInvalidError("eslint line must be integer")
                if column is not None and not isinstance(column, int):
                    raise ScannerOutputInvalidError("eslint column must be integer")
                normalized = normalize_finding_path(file_path, project_path, raw_payload=message_entry)
                findings.append(
                    Finding(
                        tool="eslint",
                        rule_id=rule_id,
                        severity=self._map_severity(rule_id, message_entry.get("severity")),
                        category=self._map_category(rule_id),
                        language=self._map_language(normalized),
                        file=normalized,
                        line=line,
                        column=column,
                        message=message,
                        raw_payload=message_entry,
                    )
                )
        return findings

    def _map_severity(self, rule_id: str, level: object) -> Severity:
        mapped = _select_by_prefix(rule_id, self.mapping.severity_prefixes, self.mapping.default_severity)
        if isinstance(level, int):
            if level >= 2:
                return Severity.high if mapped in {Severity.high, Severity.critical} else Severity.medium
            if level == 1:
                return Severity.low if mapped == Severity.low else Severity.medium
        return mapped

    def _map_category(self, rule_id: str) -> Category:
        return _select_by_prefix(rule_id, self.mapping.category_prefixes, self.mapping.default_category)

    @staticmethod
    def _map_language(path: Path) -> Language:
        suffix = path.suffix.lower()
        if suffix in {".ts", ".tsx"}:
            return Language.typescript
        return Language.javascript
