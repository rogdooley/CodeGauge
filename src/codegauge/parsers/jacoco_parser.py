from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from ..domain.models import Finding
from .base import ScannerParser
from .formats import parse_xml_document, parse_float


class JaCoCoParser(ScannerParser):
    parser_name = "jacoco_parser"
    supported_scanners = ("jacoco",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        if not stdout.strip():
            return []
        self._extract_scalar_metrics(stdout)
        return []

    def parse_metadata(self, stdout: str, stderr: str, project_path: Path) -> dict[str, Any]:
        if not stdout.strip():
            return {}
        return {"scalar_metrics": self._extract_scalar_metrics(stdout)}

    def _extract_scalar_metrics(self, stdout: str) -> dict[str, float | int]:
        root = parse_xml_document(stdout, scanner_name="jacoco")
        counters: dict[str, tuple[int, int]] = {}
        for counter in root.findall(".//counter"):
            type_name = counter.attrib.get("type")
            covered = counter.attrib.get("covered")
            missed = counter.attrib.get("missed")
            if not type_name or covered is None or missed is None:
                continue
            covered_i = int(parse_float(covered, context=f"jacoco {type_name} covered"))
            missed_i = int(parse_float(missed, context=f"jacoco {type_name} missed"))
            counters[type_name.upper()] = (covered_i, missed_i)

        line_cov = self._percent(counters.get("LINE"))
        branch_cov = self._percent(counters.get("BRANCH"))
        class_count = sum(counters.get("CLASS", (0, 0)))
        method_count = sum(counters.get("METHOD", (0, 0)))
        return {
            "coverage_percent": line_cov,
            "branch_coverage_percent": branch_cov,
            "class_count": class_count,
            "method_count": method_count,
        }

    @staticmethod
    def _percent(counter: tuple[int, int] | None) -> float:
        if counter is None:
            return 0.0
        covered, missed = counter
        total = covered + missed
        if total <= 0:
            return 0.0
        return round((covered / total) * 100.0, 2)

