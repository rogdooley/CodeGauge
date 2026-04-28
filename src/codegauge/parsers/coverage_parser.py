from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from ..domain.models import Finding
from .base import ScannerOutputInvalidError, ScannerParser
from .formats.json_parser import parse_json_document, require_object


class CoverageParser(ScannerParser):
    parser_name = "coverage_parser"
    supported_scanners = ("coverage",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        # coverage produces scalar metrics only.
        if not stdout.strip():
            return []
        self._extract_coverage_percent(stdout)
        return []

    def parse_metadata(self, stdout: str, stderr: str, project_path: Path) -> dict[str, Any]:
        if not stdout.strip():
            return {}
        coverage_percent = self._extract_coverage_percent(stdout)
        return {"scalar_metrics": {"coverage_percent": coverage_percent}}

    def _extract_coverage_percent(self, stdout: str) -> float:
        payload = parse_json_document(stdout, scanner_name="coverage")
        root = require_object(payload, context="coverage payload")
        totals = require_object(root.get("totals"), context="coverage totals")
        coverage_percent = totals.get("percent_covered")
        if isinstance(coverage_percent, (int, float)):
            return float(coverage_percent)
        raise ScannerOutputInvalidError("coverage totals.percent_covered must be numeric")
