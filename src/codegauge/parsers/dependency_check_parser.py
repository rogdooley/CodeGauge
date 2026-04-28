from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerParser, normalize_finding_path
from .formats import parse_json_document, require_list, require_object, require_string


class DependencyCheckParser(ScannerParser):
    parser_name = "dependency_check_parser"
    supported_scanners = ("dependency_check",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        payload = parse_json_document(stdout, scanner_name="dependency_check")
        roots: list[dict] = []
        if isinstance(payload, list):
            roots = [require_object(item, context="dependency-check payload") for item in payload if isinstance(item, dict)]
        else:
            roots = [require_object(payload, context="dependency-check payload")]
        findings: list[Finding] = []
        for root in roots:
            dependencies = require_list(root.get("dependencies") or [], context="dependency-check dependencies")
            for dep_obj in dependencies:
                dependency = require_object(dep_obj, context="dependency-check dependency")
                file_name = require_string(
                    dependency.get("fileName")
                    or dependency.get("filePath")
                    or dependency.get("packagePath")
                    or "pom.xml",
                    context="dependency-check fileName",
                )
                vulnerabilities = require_list(
                    dependency.get("vulnerabilities") or [],
                    context="dependency-check vulnerabilities",
                )
                for vuln_obj in vulnerabilities:
                    vulnerability = require_object(vuln_obj, context="dependency-check vulnerability")
                    rule_id = require_string(
                        vulnerability.get("name") or vulnerability.get("source") or "DEPENDENCY_CHECK",
                        context="dependency-check vulnerability name",
                    )
                    message = vulnerability.get("description") or vulnerability.get("notes") or rule_id
                    if not isinstance(message, str):
                        message = rule_id
                    raw_payload = dict(vulnerability)
                    normalized_path = normalize_finding_path(file_name, project_path, raw_payload=raw_payload)
                    findings.append(
                        Finding(
                            tool="dependency_check",
                            rule_id=rule_id,
                            severity=self._severity(vulnerability.get("severity"), vulnerability.get("cvssv3", {})),
                            category=Category.security,
                            language=Language.java,
                            file=normalized_path,
                            line=None,
                            column=None,
                            message=message.strip(),
                            raw_payload=raw_payload,
                        )
                    )
        return findings

    @staticmethod
    def _severity(value: object, cvss: object) -> Severity:
        if isinstance(value, str):
            normalized = value.strip().upper()
            if normalized in {"CRITICAL"}:
                return Severity.critical
            if normalized in {"HIGH"}:
                return Severity.high
            if normalized in {"MEDIUM"}:
                return Severity.medium
            if normalized in {"LOW"}:
                return Severity.low
        if isinstance(cvss, dict):
            score = cvss.get("baseScore")
            if isinstance(score, (int, float)):
                if score >= 9.0:
                    return Severity.critical
                if score >= 7.0:
                    return Severity.high
                if score >= 4.0:
                    return Severity.medium
                return Severity.low
        return Severity.medium
