from __future__ import annotations

import re
from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerParser
from .formats import parse_json_document, require_object, require_string

_CHECK_LINE_RE = re.compile(r"^(?P<target>[^:]+):\s*\((?P<rule>[A-Za-z0-9_.-]+)\)\s*(?P<message>.+)$")
_CHECK_INLINE_RE = re.compile(r"\((?P<rule>[A-Za-z0-9_.-]+)\)\s*(?P<message>[^\n]+)")


class DjangoCheckDeployParser(ScannerParser):
    parser_name = "django_check_deploy_parser"
    supported_scanners = ("django_check_deploy",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        payload = parse_json_document(stdout or "{}", scanner_name="django_check_deploy")
        root = require_object(payload, context="django check --deploy payload")
        check_stdout = require_string(root.get("stdout") or "", context="django check stdout")
        check_stderr = str(root.get("stderr") or "")
        combined = "\n".join(part for part in (check_stdout, check_stderr) if part)

        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for line in combined.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            matched = _CHECK_LINE_RE.match(stripped)
            if matched:
                rule = matched.group("rule")
                message = matched.group("message").strip()
                self._append_finding(findings, seen, rule, message, line)
                continue
            for inline in _CHECK_INLINE_RE.finditer(stripped):
                rule = inline.group("rule")
                message = inline.group("message").strip()
                self._append_finding(findings, seen, rule, message, line)
        return findings

    def _append_finding(
        self,
        findings: list[Finding],
        seen: set[tuple[str, str]],
        rule: str,
        message: str,
        raw_line: str,
    ) -> None:
        rule_id = f"DJG.CHECK.{rule.upper()}"
        key = (rule_id, message)
        if key in seen:
            return
        seen.add(key)
        findings.append(
            Finding(
                tool="django_check_deploy",
                rule_id=rule_id,
                severity=self._severity_for_rule(rule_id),
                category=Category.security,
                language=Language.python,
                file=Path("manage.py"),
                line=1,
                message=message,
                raw_payload={"line": raw_line},
            )
        )

    @staticmethod
    def _severity_for_rule(rule_id: str) -> Severity:
        if "CRITICAL" in rule_id or rule_id.endswith(".W001"):
            return Severity.high
        if rule_id.endswith(".W004") or rule_id.endswith(".W008"):
            return Severity.medium
        return Severity.low
