from __future__ import annotations

from codegauge.domain.models import Severity
from codegauge.scoring.models import CategoryScore, Grade, NormalizedMetric, ScoreCard, ScoreCategory


def test_scoring_model_serialization() -> None:
    card = ScoreCard(
        overall_score=84.2,
        category_scores=[
            CategoryScore(
                category=ScoreCategory.security,
                score=90,
                finding_count=2,
                weight=0.4,
                summary="Security posture is strong",
            ),
            CategoryScore(
                category=ScoreCategory.lint,
                score=78,
                finding_count=10,
                weight=0.2,
                summary="Lint quality is moderate",
            ),
        ],
        grade=Grade.B,
        finding_counts={ScoreCategory.security: 2, ScoreCategory.lint: 10},
        warnings=["coverage missing"],
    )
    payload = card.model_dump(mode="json")
    assert payload["overall_score"] == 84.2
    assert payload["grade"] == "B"
    assert payload["category_scores"][0]["category"] == "security"
    assert payload["finding_counts"]["security"] == 2


def test_normalized_metric_serialization() -> None:
    metric = NormalizedMetric(
        category=ScoreCategory.security,
        severity=Severity.high,
        count=3,
        score_hint=1.5,
        source="bandit",
    )
    payload = metric.model_dump(mode="json")
    assert payload["category"] == "security"
    assert payload["severity"] == "high"
    assert payload["count"] == 3
    assert payload["score_hint"] == 1.5
    assert payload["source"] == "bandit"
