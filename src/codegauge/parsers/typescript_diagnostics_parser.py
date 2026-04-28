from __future__ import annotations

import re
from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerParser, normalize_finding_path
from .formats import parse_json_document, require_list, require_object, require_string

_TSC_LINE = re.compile(
    r"^(?P<file>.+?)\((?P<line>\d+),(?P<column>\d+)\):\s*error\s*(?P<code>TS\d+):\s*(?P<message>.+)$"
)
_TSC_PRETTY_LINE = re.compile(
    r"^error\s+TS(?P<code>\d+):\s*(?P<message>.+?)\s+at\s+(?P<file>.+?):(?P<line>\d+):(?P<column>\d+)$",
    re.IGNORECASE,
)


class TypeScriptDiagnosticsParser(ScannerParser):
    parser_name = "typescript_diagnostics_parser"
    supported_scanners = ("typescript_diagnostics",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        findings: list[Finding] = []
        payload = self._extract_json_payload(stdout, stderr)
        if payload is not None:
            return self._parse_json_payload(payload, project_path)

        combined = "\n".join(part for part in (stdout, stderr) if part)
        for line in combined.splitlines():
            match = _TSC_LINE.match(line.strip())
            if match:
                self._append_finding(
                    findings,
                    project_path,
                    file_raw=match.group("file"),
                    code=match.group("code"),
                    message=match.group("message").strip(),
                    line=int(match.group("line")),
                    column=int(match.group("column")),
                    raw_payload={"line": line},
                )
                continue
            pretty = _TSC_PRETTY_LINE.match(line.strip())
            if pretty:
                code = f"TS{pretty.group('code')}"
                self._append_finding(
                    findings,
                    project_path,
                    file_raw=pretty.group("file"),
                    code=code,
                    message=pretty.group("message").strip(),
                    line=int(pretty.group("line")),
                    column=int(pretty.group("column")),
                    raw_payload={"line": line},
                )
        return findings

    def _parse_json_payload(self, payload: dict, project_path: Path) -> list[Finding]:
        diagnostics = require_list(payload.get("diagnostics") or [], context="typescript diagnostics")
        findings: list[Finding] = []
        for item in diagnostics:
            entry = require_object(item, context="typescript diagnostic")
            file_raw = require_string(entry.get("file"), context="typescript diagnostic file")
            code = str(entry.get("code") or "TS0000")
            if not code.startswith("TS"):
                code = f"TS{code}"
            message = require_string(entry.get("message"), context="typescript diagnostic message")
            line = entry.get("line")
            column = entry.get("column")
            if not isinstance(line, int):
                line = 1
            if not isinstance(column, int):
                column = 1
            self._append_finding(
                findings,
                project_path,
                file_raw=file_raw,
                code=code,
                message=message,
                line=line,
                column=column,
                raw_payload=entry,
            )
        return findings

    @staticmethod
    def _extract_json_payload(stdout: str, stderr: str) -> dict | None:
        for blob in (stdout, stderr):
            candidate = (blob or "").strip()
            if not candidate.startswith("{"):
                continue
            try:
                parsed = parse_json_document(candidate, scanner_name="typescript_diagnostics")
            except Exception:
                continue
            if isinstance(parsed, dict):
                return parsed
        return None

    def _append_finding(
        self,
        findings: list[Finding],
        project_path: Path,
        *,
        file_raw: str,
        code: str,
        message: str,
        line: int,
        column: int,
        raw_payload: dict,
    ) -> None:
        normalized = normalize_finding_path(file_raw, project_path)
        findings.append(
            Finding(
                tool="typescript_diagnostics",
                rule_id=code,
                severity=self._severity(code),
                category=self._category(code),
                language=Language.typescript,
                file=normalized,
                line=line,
                column=column,
                message=message,
                raw_payload=raw_payload,
            )
        )

    @staticmethod
    def _severity(code: str) -> Severity:
        if code in {"TS2307", "TS7006", "TS2322"}:
            return Severity.high
        return Severity.medium

    @staticmethod
    def _category(code: str) -> Category:
        if code.startswith("TS7") or code.startswith("TS2"):
            return Category.typing
        return Category.lint
