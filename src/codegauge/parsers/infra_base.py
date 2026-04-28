from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerOutputInvalidError, normalize_finding_path
from .formats import parse_json_document, require_list, require_object, require_string


def parse_infra_findings_payload(
    *,
    stdout: str,
    scanner_name: str,
    tool: str,
    category: Category,
    language: Language = Language.general,
    project_path: Path,
) -> tuple[list[Finding], dict[str, Any]]:
    payload = parse_json_document(stdout or "{}", scanner_name=scanner_name)
    root = require_object(payload, context=f"{scanner_name} payload")
    entries = require_list(root.get("findings") or [], context=f"{scanner_name} findings")
    findings: list[Finding] = []
    for item in entries:
        entry = require_object(item, context=f"{scanner_name} finding")
        rule_id = require_string(entry.get("rule_id"), context=f"{scanner_name} rule_id")
        file_value = require_string(entry.get("file"), context=f"{scanner_name} file")
        message = require_string(entry.get("message"), context=f"{scanner_name} message")
        line = entry.get("line")
        if line is not None and not isinstance(line, int):
            raise ScannerOutputInvalidError(f"{scanner_name} line must be integer")
        normalized = normalize_finding_path(file_value, project_path, raw_payload=entry)
        findings.append(
            Finding(
                tool=tool,
                rule_id=rule_id,
                severity=_severity(entry.get("severity")),
                category=category,
                language=language,
                file=normalized,
                line=line,
                message=message,
                raw_payload=entry,
            )
        )
    scalar_metrics = root.get("scalar_metrics") if isinstance(root.get("scalar_metrics"), dict) else {}
    return findings, {"scalar_metrics": scalar_metrics} if scalar_metrics else {}


def _severity(value: object) -> Severity:
    text = str(value or "").lower()
    if text == "critical":
        return Severity.critical
    if text == "high":
        return Severity.high
    if text == "low":
        return Severity.low
    if text == "info":
        return Severity.info
    return Severity.medium
