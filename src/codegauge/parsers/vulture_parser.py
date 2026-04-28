from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Category, Finding, Language, Severity
from .base import ScannerOutputInvalidError, ScannerParser, normalize_finding_path
from .formats.json_parser import parse_json_document, require_list, require_object, require_string


class VultureParser(ScannerParser):
    parser_name = "vulture_parser"
    supported_scanners = ("vulture",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        payload = parse_json_document(stdout, scanner_name="vulture")
        entries = require_list(payload, context="vulture findings")

        findings: list[Finding] = []
        for item in entries:
            entry = require_object(item, context="vulture finding")
            filename = require_string(entry.get("filename"), context="vulture filename")
            normalized_path = normalize_finding_path(filename, project_path, raw_payload=entry)

            first_line = entry.get("first_line")
            if first_line is not None and not isinstance(first_line, int):
                raise ScannerOutputInvalidError("vulture first_line must be an integer")
            size = entry.get("size")
            if size is not None and not isinstance(size, int):
                raise ScannerOutputInvalidError("vulture size must be an integer")

            name = str(entry.get("name") or "<unknown>")
            typ = str(entry.get("type") or entry.get("typ") or "symbol")
            findings.append(
                Finding(
                    tool="vulture",
                    rule_id="VULTURE_UNUSED",
                    severity=Severity.low,
                    category=Category.dead_code,
                    language=Language.python,
                    file=normalized_path,
                    line=first_line,
                    column=None,
                    message=f"Unused {typ}: {name}" + (f" (size={size})" if size is not None else ""),
                    raw_payload=entry,
                )
            )
        return findings
