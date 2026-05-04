from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Finding
from ..domain.models import Severity
from .base import ScannerParser
from .formats.json_parser import parse_json_document, require_list, require_object, require_string
from .secrets_parser_common import _secret_finding


class SecretsHeuristicParser(ScannerParser):
    parser_name = "secrets_heuristic_parser"
    supported_scanners = ("secrets_heuristic",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        del stderr
        if not stdout.strip():
            return []
        payload = parse_json_document(stdout, scanner_name="secrets_heuristic")
        root = require_object(payload, context="secrets heuristic payload")
        rows = require_list(root.get("findings") or [], context="secrets heuristic findings")
        findings = []
        for item in rows:
            entry = require_object(item, context="secrets heuristic finding")
            file_value = require_string(entry.get("file"), context="secrets heuristic file")
            finding_type = require_string(entry.get("type"), context="secrets heuristic type")
            message = require_string(entry.get("message") or "Secret hygiene finding", context="secrets heuristic message")
            confidence = str(entry.get("confidence") or "weak").lower()
            line = entry.get("line")
            if not isinstance(line, int):
                line = None
            severity = Severity.medium
            if finding_type == "probable_secret_exposure":
                severity = Severity.high
            elif finding_type == "intentional_bearer_issuance_url_transport":
                severity_value = str(entry.get("severity") or "medium").lower()
                if severity_value == "high":
                    severity = Severity.high
                elif severity_value == "low":
                    severity = Severity.low
                else:
                    severity = Severity.medium
            elif confidence == "weak" or finding_type == "weak_secret_management":
                severity = Severity.medium
            elif finding_type == "sensitive_path":
                finding_type = "weak_secret_management"
                severity = Severity.low
            if finding_type not in {
                "probable_secret_exposure",
                "weak_secret_management",
                "intentional_bearer_issuance_url_transport",
            }:
                finding_type = "weak_secret_management"
            confidence_score = 0.35
            if confidence == "probable":
                confidence_score = 0.75
            elif confidence == "high":
                confidence_score = 0.9
            findings.append(
                _secret_finding(
                    tool="secrets_heuristic",
                    rule_id=finding_type,
                    file_value=file_value,
                    message=message,
                    project_path=project_path,
                    line=line,
                    severity=severity,
                    tags=["heuristic", "secrets_profile", confidence],
                    confidence=confidence_score,
                    raw_payload={**entry, "confidence": confidence, "verified": False, "secret_real": False},
                )
            )
        return findings

    def parse_metadata(self, stdout: str, stderr: str, project_path: Path) -> dict[str, object]:
        del stderr, project_path
        if not stdout.strip():
            return {}
        payload = parse_json_document(stdout, scanner_name="secrets_heuristic")
        root = require_object(payload, context="secrets heuristic payload")
        scalar_metrics = root.get("scalar_metrics")
        if not isinstance(scalar_metrics, dict):
            return {}
        return {"scalar_metrics": dict(scalar_metrics)}
