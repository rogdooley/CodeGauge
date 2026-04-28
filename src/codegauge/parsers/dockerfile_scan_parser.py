from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from ..domain.models import Category, Finding, Language
from .base import ScannerParser
from .infra_base import parse_infra_findings_payload


class DockerfileScanParser(ScannerParser):
    parser_name = "dockerfile_scan_parser"
    supported_scanners = ("dockerfile_scan",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        findings, _ = parse_infra_findings_payload(
            stdout=stdout,
            scanner_name="dockerfile_scan",
            tool="dockerfile_scan",
            category=Category.security,
            language=Language.general,
            project_path=project_path,
        )
        return findings

    def parse_metadata(self, stdout: str, stderr: str, project_path: Path) -> dict[str, Any]:
        _, metadata = parse_infra_findings_payload(
            stdout=stdout,
            scanner_name="dockerfile_scan",
            tool="dockerfile_scan",
            category=Category.security,
            language=Language.general,
            project_path=project_path,
        )
        return metadata
