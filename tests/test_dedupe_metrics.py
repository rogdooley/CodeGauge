from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from codegauge.domain.models import Category, Finding, Language, ScanResult, Severity
from codegauge.services.metrics import MetricsExtractor
from codegauge.scoring.models import ScoreCategory


def _result(scanner: str, finding: Finding) -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        scanner_name=scanner,
        started_at=now,
        completed_at=now,
        duration_ms=1.0,
        findings=[finding],
        success=True,
        metadata={},
    )


def test_duplicate_findings_suppressed_for_scoring_only() -> None:
    finding_a = Finding(
        tool="ruff",
        rule_id="F401",
        severity=Severity.low,
        category=Category.dead_code,
        language=Language.python,
        file=Path("src/a.py"),
        line=5,
        message="Unused import foo",
    )
    finding_b = Finding(
        tool="vulture",
        rule_id="F401",
        severity=Severity.low,
        category=Category.dead_code,
        language=Language.python,
        file=Path("src/a.py"),
        line=5,
        message="unused   import foo",
    )

    extractor = MetricsExtractor()
    metrics = extractor.extract_from_scan_results([_result("ruff", finding_a), _result("vulture", finding_b)])

    dead_code_metric = next(metric for metric in metrics if metric.category == ScoreCategory.dead_code)
    assert dead_code_metric.count == 1
    dedupe = extractor.last_duplicate_metadata
    assert dedupe["suppressed_count"] == 1
    assert dedupe["total_findings"] == 2
    assert dedupe["net_findings"] == 1
    assert dedupe["suppressed_per_scanner"]["vulture"] == 1
    assert dedupe["suppressed"]
