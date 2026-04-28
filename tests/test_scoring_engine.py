from __future__ import annotations

from codegauge.domain.models import Severity
from codegauge.scoring.engine import CodeGaugeScoringEngine
from codegauge.scoring.models import Grade, NormalizedMetric, ScoreCategory


def _security_high(count: int) -> list[NormalizedMetric]:
    return [
        NormalizedMetric(
            category=ScoreCategory.security,
            severity=Severity.high,
            count=count,
            score_hint=1.0,
            source="bandit",
        )
    ]


def test_scoring_engine_returns_scorecard() -> None:
    engine = CodeGaugeScoringEngine()
    card = engine.score(
        [
            NormalizedMetric(
                category=ScoreCategory.security,
                severity=Severity.high,
                count=2,
                score_hint=1.0,
                source="bandit",
            ),
            NormalizedMetric(
                category=ScoreCategory.lint,
                severity=Severity.low,
                count=5,
                score_hint=1.0,
                source="ruff",
            ),
        ]
    )

    assert isinstance(card.overall_score, float)
    assert len(card.category_scores) == len(ScoreCategory)
    assert card.finding_counts[ScoreCategory.security] == 2
    assert card.grade in {Grade.A, Grade.B, Grade.C, Grade.D, Grade.F}


def test_scoring_engine_grade_thresholds() -> None:
    engine = CodeGaugeScoringEngine()

    assert engine.score(_security_high(0)).grade == Grade.A
    assert engine.score(_security_high(4)).grade == Grade.B
    assert engine.score(_security_high(7)).grade == Grade.C
    assert (
        engine.score(
            _security_high(10)
            + [
                NormalizedMetric(
                    category=ScoreCategory.lint,
                    severity=Severity.high,
                    count=5,
                    score_hint=1.0,
                    source="ruff",
                )
            ]
        ).grade
        == Grade.D
    )
    assert (
        engine.score(
            _security_high(10)
            + [
                NormalizedMetric(
                    category=ScoreCategory.lint,
                    severity=Severity.high,
                    count=10,
                    score_hint=1.0,
                    source="ruff",
                )
            ]
        ).grade
        == Grade.F
    )


def test_scoring_engine_is_deterministic() -> None:
    engine = CodeGaugeScoringEngine()
    metrics = [
        NormalizedMetric(
            category=ScoreCategory.security,
            severity=Severity.medium,
            count=3,
            score_hint=1.2,
            source="ruff",
        ),
        NormalizedMetric(
            category=ScoreCategory.dead_code,
            severity=Severity.low,
            count=4,
            score_hint=0.8,
            source="ruff",
        ),
    ]

    first = engine.score(metrics)
    second = engine.score(metrics)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
