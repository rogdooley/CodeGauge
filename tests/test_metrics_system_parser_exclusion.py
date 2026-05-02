from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from codegauge.domain.models import Category, Finding, Language, ScanResult, Severity
from codegauge.services.metrics.base import FindingMetricProvider


def test_system_parser_findings_are_excluded_from_score_metrics() -> None:
    provider = FindingMetricProvider()
    now = datetime.now(UTC)
    scan_result = ScanResult(
        scanner_name="ruff",
        started_at=now,
        completed_at=now,
        duration_ms=1.0,
        success=True,
        findings=[
            Finding(
                tool="codegauge",
                rule_id="CODEGAUGE.PARSER.UNHANDLED",
                severity=Severity.medium,
                category=Category.system_parser,
                language=Language.general,
                file=Path("scanners/ruff"),
                message="parser failure",
            ),
            Finding(
                tool="ruff",
                rule_id="F401",
                severity=Severity.low,
                category=Category.dead_code,
                language=Language.python,
                file=Path("src/a.py"),
                message="unused import",
            ),
        ],
    )

    metrics = provider.extract(scan_result)
    assert len(metrics) == 1
    assert metrics[0].category.value == "dead_code"
