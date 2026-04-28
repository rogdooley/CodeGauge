from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerOutputInvalidError, ScannerParser
from .formats import parse_json_document, require_object


class NPMAuditParser(ScannerParser):
    parser_name = "npm_audit_parser"
    supported_scanners = ("npm_audit",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        envelope = parse_json_document(stdout, scanner_name="npm_audit")
        root = require_object(envelope, context="npm audit envelope")
        audit_stdout = root.get("stdout") if isinstance(root.get("stdout"), str) else stdout
        tool_name = str(root.get("tool") or "npm")
        payload = parse_json_document(audit_stdout, scanner_name="npm_audit")
        root = require_object(payload, context="npm audit payload")

        findings = self._parse_npm_v2(root)
        if findings:
            return findings
        findings = self._parse_npm_v1(root)
        if findings:
            return findings
        findings = self._parse_yarn_audit(root)
        if findings:
            return findings

        if tool_name in {"npm", "pnpm", "yarn"}:
            return []
        raise ScannerOutputInvalidError("unsupported npm audit schema")

    def _parse_npm_v2(self, root: dict) -> list[Finding]:
        vulns = root.get("vulnerabilities")
        if vulns is None:
            return []
        if not isinstance(vulns, dict):
            raise ScannerOutputInvalidError("npm audit vulnerabilities must be object")

        findings: list[Finding] = []
        for package_name in sorted(vulns.keys()):
            vuln = vulns[package_name]
            if not isinstance(vuln, dict):
                continue
            severity = self._severity(str(vuln.get("severity") or ""))
            via = vuln.get("via")
            source = ""
            message = ""
            if isinstance(via, list) and via:
                first = via[0]
                if isinstance(first, dict):
                    source = str(first.get("source") or "")
                    message = str(first.get("title") or first.get("name") or "")
                else:
                    source = str(first)
            message = str(vuln.get("title") or message or f"Vulnerability in dependency: {package_name}")
            rule_id = f"NPM.AUDIT.{str(source or package_name).upper()}"
            findings.append(
                Finding(
                    tool="npm_audit",
                    rule_id=rule_id,
                    severity=severity,
                    category=Category.security,
                    language=Language.javascript,
                    file=Path("package.json"),
                    line=1,
                    message=message,
                    raw_payload=vuln,
                )
            )
        return findings

    def _parse_npm_v1(self, root: dict) -> list[Finding]:
        advisories = root.get("advisories")
        if advisories is None:
            return []
        if not isinstance(advisories, dict):
            raise ScannerOutputInvalidError("npm audit advisories must be object")
        findings: list[Finding] = []
        for advisory_id in sorted(advisories.keys()):
            advisory = advisories[advisory_id]
            if not isinstance(advisory, dict):
                continue
            package = str(advisory.get("module_name") or "unknown")
            title = str(advisory.get("title") or f"Vulnerability in dependency: {package}")
            severity = self._severity(str(advisory.get("severity") or ""))
            rule_id = f"NPM.AUDIT.{str(advisory.get('cves') or advisory_id).upper()}"
            findings.append(
                Finding(
                    tool="npm_audit",
                    rule_id=rule_id,
                    severity=severity,
                    category=Category.security,
                    language=Language.javascript,
                    file=Path("package.json"),
                    line=1,
                    message=title,
                    raw_payload=advisory,
                )
            )
        return findings

    def _parse_yarn_audit(self, root: dict) -> list[Finding]:
        data = root.get("data")
        if not isinstance(data, dict):
            return []
        advisory = data.get("advisory")
        if not isinstance(advisory, dict):
            return []
        module_name = str(advisory.get("module_name") or "unknown")
        title = str(advisory.get("title") or f"Vulnerability in dependency: {module_name}")
        severity = self._severity(str(advisory.get("severity") or ""))
        identifier = advisory.get("id") or advisory.get("cves") or module_name
        rule_id = f"NPM.AUDIT.{str(identifier).upper()}"
        return [
            Finding(
                tool="npm_audit",
                rule_id=rule_id,
                severity=severity,
                category=Category.security,
                language=Language.javascript,
                file=Path("package.json"),
                line=1,
                message=title,
                raw_payload=advisory,
            )
        ]

    @staticmethod
    def _severity(value: str) -> Severity:
        normalized = value.strip().lower()
        if normalized in {"critical"}:
            return Severity.critical
        if normalized in {"high"}:
            return Severity.high
        if normalized in {"low"}:
            return Severity.low
        if normalized in {"info", "informational"}:
            return Severity.info
        return Severity.medium
