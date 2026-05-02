from __future__ import annotations

from pathlib import Path

from ..domain.models import Category, Finding, Language, Severity
from .base import normalize_finding_path


def _secret_finding(
    *,
    tool: str,
    rule_id: str,
    file_value: str,
    message: str,
    project_path: Path,
    line: int | None = None,
    severity: Severity = Severity.high,
    confidence: float = 1.0,
    tags: list[str] | None = None,
    raw_payload: dict | None = None,
) -> Finding:
    payload = dict(raw_payload or {})
    payload["secret_category"] = rule_id
    return Finding(
        tool=tool,
        rule_id=rule_id,
        severity=severity,
        category=Category.security,
        language=Language.general,
        file=normalize_finding_path(file_value, project_path, raw_payload=payload),
        line=line,
        column=None,
        message=message,
        confidence=confidence,
        tags=tags or [],
        raw_payload=payload,
    )
