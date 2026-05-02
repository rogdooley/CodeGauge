from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerParser, normalize_finding_path
from .formats import parse_json_document, require_list, require_object, require_string


class PHPStanParser(ScannerParser):
    parser_name = "phpstan_parser"
    supported_scanners = ("phpstan",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        del stderr
        if not stdout.strip():
            return []
        payload = parse_json_document(stdout, scanner_name="phpstan")
        root = require_object(payload, context="phpstan payload")
        files = require_object(root.get("files") or {}, context="phpstan files")
        findings: list[Finding] = []
        for raw_file, details in sorted(files.items()):
            if not isinstance(details, dict):
                continue
            messages = require_list(details.get("messages") or [], context="phpstan messages")
            for item in messages:
                entry = require_object(item, context="phpstan message")
                message = require_string(entry.get("message") or "PHPStan issue", context="phpstan message text")
                line = entry.get("line")
                if not isinstance(line, int):
                    line = 1
                identifier = str(entry.get("identifier") or "PHPSTAN.GENERIC").upper()
                normalized = normalize_finding_path(str(raw_file), project_path, raw_payload=entry)
                findings.append(
                    Finding(
                        tool="phpstan",
                        rule_id=identifier,
                        severity=Severity.medium,
                        category=Category.maintainability,
                        language=Language.php,
                        file=normalized,
                        line=line,
                        message=message,
                        raw_payload=entry,
                    )
                )
        return findings
