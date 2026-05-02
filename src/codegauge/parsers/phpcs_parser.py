from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerParser, normalize_finding_path
from .formats import parse_json_document, require_object, require_string


class PHPCSParser(ScannerParser):
    parser_name = "phpcs_parser"
    supported_scanners = ("phpcs",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        del stderr
        if not stdout.strip():
            return []
        payload = parse_json_document(stdout, scanner_name="phpcs")
        root = require_object(payload, context="phpcs payload")
        files = root.get("files") if isinstance(root.get("files"), dict) else {}
        findings: list[Finding] = []
        for file_value, details in files.items():
            if not isinstance(details, dict):
                continue
            messages = details.get("messages") if isinstance(details.get("messages"), list) else []
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                normalized = normalize_finding_path(str(file_value), project_path, raw_payload=msg)
                severity = Severity.medium if str(msg.get("type") or "warning").lower() == "warning" else Severity.high
                findings.append(
                    Finding(
                        tool="phpcs",
                        rule_id=str(msg.get("source") or "PHPCS.GENERIC"),
                        severity=severity,
                        category=Category.lint,
                        language=Language.php,
                        file=normalized,
                        line=int(msg.get("line") or 1),
                        column=int(msg.get("column") or 1),
                        message=require_string(msg.get("message") or "PHPCS finding", context="phpcs message"),
                        raw_payload=msg,
                    )
                )
        return findings
