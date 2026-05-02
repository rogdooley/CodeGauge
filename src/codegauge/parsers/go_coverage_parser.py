from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from ..domain.models import Finding
from .base import ScannerOutputInvalidError, ScannerParser
from .formats import parse_json_document, require_object


class GoCoverageParser(ScannerParser):
    parser_name = "go_coverage_parser"
    supported_scanners = ("go_coverage",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        del stderr, project_path
        if not stdout.strip():
            return []
        self._extract_coverage_percent(stdout)
        return []

    def parse_metadata(self, stdout: str, stderr: str, project_path: Path) -> dict[str, Any]:
        del stderr, project_path
        if not stdout.strip():
            return {}
        coverage_percent = self._extract_coverage_percent(stdout)
        return {"scalar_metrics": {"coverage_percent": coverage_percent}}

    def _extract_coverage_percent(self, stdout: str) -> float:
        payload = parse_json_document(stdout, scanner_name="go_coverage")
        root = require_object(payload, context="go coverage payload")
        totals = require_object(root.get("totals"), context="go coverage totals")
        covered = totals.get("percent_covered")
        if isinstance(covered, (int, float)):
            return float(covered)
        raise ScannerOutputInvalidError("go coverage totals.percent_covered must be numeric")
