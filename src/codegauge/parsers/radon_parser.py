from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Sequence

from ..domain.models import Finding
from .base import ScannerOutputInvalidError, ScannerParser
from .formats.json_parser import parse_json_document, require_list, require_object


class RadonParser(ScannerParser):
    parser_name = "radon_parser"
    supported_scanners = ("radon",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        # Radon is modeled as scalar metrics only.
        if not stdout.strip():
            return []
        self._extract_metrics(stdout)
        return []

    def parse_metadata(self, stdout: str, stderr: str, project_path: Path) -> dict[str, Any]:
        if not stdout.strip():
            return {}
        return {"scalar_metrics": self._extract_metrics(stdout)}

    def _extract_metrics(self, stdout: str) -> dict[str, Any]:
        payload = parse_json_document(stdout, scanner_name="radon")
        root = require_object(payload, context="radon payload")
        cc_root = require_object(root.get("cc"), context="radon cc payload")
        mi_root = require_object(root.get("mi"), context="radon mi payload")

        complexities: list[int] = []
        distribution_counter: Counter[str] = Counter()

        for blocks in cc_root.values():
            entries = require_list(blocks, context="radon cc blocks")
            for entry_obj in entries:
                entry = require_object(entry_obj, context="radon cc block")
                complexity = entry.get("complexity")
                rank = entry.get("rank")
                if isinstance(complexity, int):
                    complexities.append(complexity)
                elif complexity is not None:
                    raise ScannerOutputInvalidError("radon complexity must be an integer")
                if isinstance(rank, str):
                    distribution_counter[rank.upper()] += 1
                elif rank is not None:
                    raise ScannerOutputInvalidError("radon rank must be a string")

        maintainability_values: list[float] = []
        for value in mi_root.values():
            if isinstance(value, (int, float)):
                maintainability_values.append(float(value))
                continue
            if isinstance(value, dict):
                mi_value = value.get("mi")
                if isinstance(mi_value, (int, float)):
                    maintainability_values.append(float(mi_value))
                continue
            if isinstance(value, list):
                for inner in value:
                    if isinstance(inner, (int, float)):
                        maintainability_values.append(float(inner))
                        continue
                    if isinstance(inner, dict):
                        mi_value = inner.get("mi")
                        if isinstance(mi_value, (int, float)):
                            maintainability_values.append(float(mi_value))

        average_complexity = round(sum(complexities) / len(complexities), 2) if complexities else None
        worst_complexity = max(complexities) if complexities else None
        maintainability_index = (
            round(sum(maintainability_values) / len(maintainability_values), 2)
            if maintainability_values
            else None
        )

        return {
            "average_complexity": average_complexity,
            "worst_complexity": worst_complexity,
            "complexity_distribution": dict(sorted(distribution_counter.items())),
            "complexity_grade": self._complexity_grade(average_complexity),
            "maintainability_index": maintainability_index,
            "maintainability_grade": self._maintainability_grade(maintainability_index),
        }

    @staticmethod
    def _complexity_grade(value: float | None) -> str | None:
        if value is None:
            return None
        if value <= 5:
            return "A"
        if value <= 10:
            return "B"
        if value <= 20:
            return "C"
        if value <= 30:
            return "D"
        if value <= 40:
            return "E"
        return "F"

    @staticmethod
    def _maintainability_grade(value: float | None) -> str | None:
        if value is None:
            return None
        if value >= 85:
            return "A"
        if value >= 70:
            return "B"
        if value >= 55:
            return "C"
        if value >= 40:
            return "D"
        if value >= 25:
            return "E"
        return "F"
