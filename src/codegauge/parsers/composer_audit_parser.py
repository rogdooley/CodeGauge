from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerParser
from .formats import parse_json_document, require_list, require_object


class ComposerAuditParser(ScannerParser):
    parser_name = "composer_audit_parser"
    supported_scanners = ("composer_audit",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        del stderr, project_path
        if not stdout.strip():
            return []
        payload = parse_json_document(stdout, scanner_name="composer_audit")
        root = require_object(payload, context="composer audit payload")
        advisory_payload = root.get("advisories")
        if isinstance(advisory_payload, dict):
            advisories = [item for item in advisory_payload.values() if isinstance(item, dict)]
        else:
            advisories = require_list(advisory_payload or [], context="composer audit advisories")
        findings: list[Finding] = []
        for advisory_raw in advisories:
            advisory = require_object(advisory_raw, context="composer advisory")
            package = str(advisory.get("packageName") or advisory.get("package") or "unknown")
            cve = str(advisory.get("cve") or advisory.get("advisoryId") or package).upper()
            title = str(advisory.get("title") or advisory.get("summary") or f"Composer advisory in {package}")
            severity = self._severity(str(advisory.get("severity") or advisory.get("cvss") or "medium"))
            findings.append(
                Finding(
                    tool="composer_audit",
                    rule_id=f"COMPOSER.AUDIT.{cve}",
                    severity=severity,
                    category=Category.security,
                    language=Language.php,
                    file=Path("composer.lock") if package else Path("composer.json"),
                    line=1,
                    message=title,
                    raw_payload=advisory,
                )
            )
        return findings

    @staticmethod
    def _severity(value: str) -> Severity:
        lowered = value.strip().lower()
        if "critical" in lowered:
            return Severity.critical
        if "high" in lowered:
            return Severity.high
        if "low" in lowered:
            return Severity.low
        if "info" in lowered:
            return Severity.info
        return Severity.medium
