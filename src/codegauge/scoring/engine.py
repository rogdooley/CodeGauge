from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..domain.models import Severity
from .models import CategoryScore, Grade, NormalizedMetric, ScoreCard, ScoreCategory


@dataclass(frozen=True)
class _CategoryAccumulator:
    finding_count: int = 0
    penalty: float = 0.0


class CodeGaugeScoringEngine:
    """Deterministic built-in CodeGauge v1 scoring."""

    _CATEGORY_WEIGHTS: Mapping[ScoreCategory, float] = {
        ScoreCategory.security: 0.30,
        ScoreCategory.typing: 0.10,
        ScoreCategory.lint: 0.15,
        ScoreCategory.maintainability: 0.15,
        ScoreCategory.complexity: 0.10,
        ScoreCategory.dead_code: 0.10,
        ScoreCategory.coverage: 0.10,
    }

    _SEVERITY_PENALTIES: Mapping[Severity, float] = {
        Severity.critical: 18.0,
        Severity.high: 10.0,
        Severity.medium: 5.0,
        Severity.low: 2.0,
        Severity.info: 0.0,
    }

    def score(self, metrics: Sequence[NormalizedMetric]) -> ScoreCard:
        accumulators: dict[ScoreCategory, _CategoryAccumulator] = {
            category: _CategoryAccumulator() for category in ScoreCategory
        }
        scalar_scores: dict[ScoreCategory, float] = {}

        for metric in metrics:
            if metric.scalar_name == "coverage_percent" and metric.scalar_value is not None:
                scalar_scores[ScoreCategory.coverage] = max(
                    0.0, min(100.0, float(metric.scalar_value))
                )
                continue
            current = accumulators[metric.category]
            penalty = self._SEVERITY_PENALTIES[metric.severity] * metric.count * metric.score_hint
            accumulators[metric.category] = _CategoryAccumulator(
                finding_count=current.finding_count + metric.count,
                penalty=current.penalty + penalty,
            )

        category_scores: list[CategoryScore] = []
        weighted_total = 0.0
        finding_counts: dict[ScoreCategory, int] = {}

        for category in ScoreCategory:
            accumulator = accumulators[category]
            weight = self._CATEGORY_WEIGHTS[category]
            if category in scalar_scores:
                category_score = scalar_scores[category]
            else:
                category_score = max(0.0, min(100.0, 100.0 - accumulator.penalty))
            weighted_total += category_score * weight
            finding_counts[category] = accumulator.finding_count
            category_scores.append(
                CategoryScore(
                    category=category,
                    score=round(category_score, 2),
                    finding_count=accumulator.finding_count,
                    weight=weight,
                    summary=self._category_summary(category, category_score, accumulator.finding_count),
                )
            )

        overall_score = round(weighted_total, 2)
        return ScoreCard(
            overall_score=overall_score,
            category_scores=category_scores,
            grade=self._grade_for_score(overall_score),
            finding_counts=finding_counts,
            warnings=[],
        )

    @staticmethod
    def _grade_for_score(score: float) -> Grade:
        if score >= 90:
            return Grade.A
        if score >= 80:
            return Grade.B
        if score >= 70:
            return Grade.C
        if score >= 60:
            return Grade.D
        return Grade.F

    @staticmethod
    def _category_summary(category: ScoreCategory, score: float, finding_count: int) -> str:
        if finding_count == 0:
            return f"No {category.value} findings"
        return f"{category.value} score {score:.2f} based on {finding_count} findings"
