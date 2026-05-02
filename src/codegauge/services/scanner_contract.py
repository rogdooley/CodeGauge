from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..domain.models import Finding


@dataclass(slots=True, frozen=True)
class ScanRequest:
    project_root: Path
    files: tuple[Path, ...]
    timeout_seconds: int
    config: Mapping[str, Any]


@dataclass(slots=True, frozen=True)
class ScanResponse:
    findings: tuple[Finding, ...]
    metadata: Mapping[str, Any]


@dataclass(slots=True, frozen=True)
class NormalizedFinding:
    tool: str
    rule_id: str
    native_severity: str
    severity: str
    ownership: str
    ownership_confidence: float
    fingerprint: str
    payload: Mapping[str, Any]
