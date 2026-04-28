from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from ..domain.models import Finding
from .base import ScannerParser
from .formats import parse_json_document


class JSCoverageParser(ScannerParser):
    parser_name = "js_coverage_parser"
    supported_scanners = ("js_coverage",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        return []

    def parse_metadata(self, stdout: str, stderr: str, project_path: Path) -> dict[str, Any]:
        if not stdout.strip() or stdout.strip() == "{}":
            return {}
        payload = parse_json_document(stdout, scanner_name="js_coverage")
        if not isinstance(payload, dict):
            return {}
        total = payload.get("total")
        if not isinstance(total, dict):
            return {}
        lines = total.get("lines")
        branches = total.get("branches")
        line_pct = lines.get("pct") if isinstance(lines, dict) else None
        branch_pct = branches.get("pct") if isinstance(branches, dict) else None
        scalar: dict[str, float] = {}
        if isinstance(line_pct, (int, float)):
            scalar["coverage_percent"] = float(line_pct)
        if isinstance(branch_pct, (int, float)):
            scalar["branch_coverage_percent"] = float(branch_pct)
        return {"scalar_metrics": scalar} if scalar else {}
