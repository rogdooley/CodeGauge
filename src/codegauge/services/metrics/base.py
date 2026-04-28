from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Iterable, Sequence

from ...domain.models import Category, Finding, ScanResult, Severity
from ...scoring.models import NormalizedMetric, ScoreCategory


class MetricProvider(ABC):
    @abstractmethod
    def supports(self, scanner_name: str) -> bool:
        ...

    @abstractmethod
    def extract(self, scan_result: ScanResult) -> Sequence[NormalizedMetric]:
        ...


class FindingMetricProvider(MetricProvider):
    """Findings-based metric extraction for one or more scanners."""

    def __init__(self, scanner_names: Iterable[str] | None = None) -> None:
        self._scanner_names = set(scanner_names or [])

    def supports(self, scanner_name: str) -> bool:
        return not self._scanner_names or scanner_name in self._scanner_names

    def extract(self, scan_result: ScanResult) -> Sequence[NormalizedMetric]:
        counts: dict[tuple[ScoreCategory, str], int] = defaultdict(int)
        for finding in scan_result.findings:
            category = self._to_score_category(finding.category)
            counts[(category, finding.severity.value)] += 1

        return [
            NormalizedMetric(
                category=category,
                severity=Severity(severity),
                count=count,
                score_hint=self._score_hint(scan_result.scanner_name, category),
                source=scan_result.scanner_name,
            )
            for (category, severity), count in sorted(counts.items(), key=lambda item: (item[0][0].value, item[0][1]))
        ]

    @staticmethod
    def _to_score_category(category: Category) -> ScoreCategory:
        return ScoreCategory(category.value)

    @staticmethod
    def _score_hint(source: str, category: ScoreCategory) -> float:
        if source == "bandit":
            return 1.5
        if source in {"dependency_check", "spotbugs", "npm_audit", "django_check_deploy"}:
            return 1.4
        if source == "coverage":
            return 1.0
        if category == ScoreCategory.security:
            return 1.2
        if category == ScoreCategory.dead_code:
            return 0.8
        if category == ScoreCategory.lint:
            return 0.75
        return 1.0


class ScalarMetricProvider(MetricProvider):
    """Scalar metric extraction from scan metadata."""

    def __init__(self, scanner_names: Iterable[str]) -> None:
        self._scanner_names = set(scanner_names)

    def supports(self, scanner_name: str) -> bool:
        return scanner_name in self._scanner_names

    def extract(self, scan_result: ScanResult) -> Sequence[NormalizedMetric]:
        scalar_metrics = scan_result.metadata.get("scalar_metrics")
        if not isinstance(scalar_metrics, dict):
            return []

        metrics: list[NormalizedMetric] = []
        for name, value in sorted(scalar_metrics.items()):
            if name == "coverage_percent" and isinstance(value, (int, float)):
                coverage = max(0.0, min(100.0, float(value)))
                metrics.append(
                    NormalizedMetric(
                        category=ScoreCategory.coverage,
                        severity=Severity.info,
                        count=1,
                        score_hint=1.0,
                        source=scan_result.scanner_name,
                        scalar_name="coverage_percent",
                        scalar_value=coverage,
                    )
                )
            if name == "branch_coverage_percent" and isinstance(value, (int, float)):
                branch_coverage = max(0.0, min(100.0, float(value)))
                metrics.append(
                    NormalizedMetric(
                        category=ScoreCategory.coverage,
                        severity=Severity.info,
                        count=1,
                        score_hint=1.0,
                        source=scan_result.scanner_name,
                        scalar_name="branch_coverage_percent",
                        scalar_value=branch_coverage,
                    )
                )
            if name == "maintainability_index" and isinstance(value, (int, float)):
                maintainability = max(0.0, min(100.0, float(value)))
                metrics.append(
                    NormalizedMetric(
                        category=ScoreCategory.maintainability,
                        severity=Severity.info,
                        count=1,
                        score_hint=1.0,
                        source=scan_result.scanner_name,
                        scalar_name="maintainability_index",
                        scalar_value=maintainability,
                    )
                )
            if name == "duplication_percent" and isinstance(value, (int, float)):
                duplication = max(0.0, min(100.0, float(value)))
                metrics.append(
                    NormalizedMetric(
                        category=ScoreCategory.maintainability,
                        severity=Severity.info,
                        count=1,
                        score_hint=1.0,
                        source=scan_result.scanner_name,
                        scalar_name="duplication_percent",
                        scalar_value=duplication,
                    )
                )
            if name == "avg_complexity" and isinstance(value, (int, float)):
                avg_complexity = max(0.0, float(value))
                metrics.append(
                    NormalizedMetric(
                        category=ScoreCategory.complexity,
                        severity=Severity.info,
                        count=1,
                        score_hint=1.0,
                        source=scan_result.scanner_name,
                        scalar_name="avg_complexity",
                        scalar_value=avg_complexity,
                    )
                )
            if name == "worst_complexity" and isinstance(value, (int, float)):
                worst_complexity = max(0.0, float(value))
                metrics.append(
                    NormalizedMetric(
                        category=ScoreCategory.complexity,
                        severity=Severity.info,
                        count=1,
                        score_hint=1.0,
                        source=scan_result.scanner_name,
                        scalar_name="worst_complexity",
                        scalar_value=worst_complexity,
                    )
                )
            if name == "class_count" and isinstance(value, (int, float)):
                class_count = max(0.0, float(value))
                metrics.append(
                    NormalizedMetric(
                        category=ScoreCategory.maintainability,
                        severity=Severity.info,
                        count=1,
                        score_hint=1.0,
                        source=scan_result.scanner_name,
                        scalar_name="class_count",
                        scalar_value=class_count,
                    )
                )
            if name == "method_count" and isinstance(value, (int, float)):
                method_count = max(0.0, float(value))
                metrics.append(
                    NormalizedMetric(
                        category=ScoreCategory.maintainability,
                        severity=Severity.info,
                        count=1,
                        score_hint=1.0,
                        source=scan_result.scanner_name,
                        scalar_name="method_count",
                        scalar_value=method_count,
                    )
                )
        return metrics
