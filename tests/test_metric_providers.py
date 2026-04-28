from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from codegauge.domain.models import Category, Finding, Language, ScanResult, Severity
from codegauge.scoring.models import ScoreCategory
from codegauge.services.metrics import FindingMetricProvider, MetricsExtractor, ScalarMetricProvider


def _scan_result(
    scanner_name: str,
    *,
    findings: list[Finding] | None = None,
    metadata: dict | None = None,
    success: bool = True,
) -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        scanner_name=scanner_name,
        started_at=now,
        completed_at=now,
        duration_ms=1.0,
        findings=findings or [],
        metadata=metadata or {},
        success=success,
    )


def test_finding_metric_provider_extracts_findings() -> None:
    finding = Finding(
        tool="pyright",
        rule_id="reportMissingImports",
        severity=Severity.high,
        category=Category.typing,
        language=Language.python,
        file=Path("src/a.py"),
        line=1,
        message="Missing import",
    )
    provider = FindingMetricProvider(scanner_names={"pyright"})
    metrics = provider.extract(_scan_result("pyright", findings=[finding]))
    assert len(metrics) == 1
    assert metrics[0].category == ScoreCategory.typing
    assert metrics[0].severity == Severity.high


def test_scalar_metric_provider_extracts_coverage_percent() -> None:
    provider = ScalarMetricProvider(scanner_names={"coverage"})
    metrics = provider.extract(
        _scan_result("coverage", metadata={"scalar_metrics": {"coverage_percent": 84.4}})
    )
    assert len(metrics) == 1
    metric = metrics[0]
    assert metric.category == ScoreCategory.coverage
    assert metric.scalar_name == "coverage_percent"
    assert metric.scalar_value == 84.4


def test_metrics_extractor_supports_findings_and_scalar() -> None:
    finding = Finding(
        tool="ruff",
        rule_id="F401",
        severity=Severity.low,
        category=Category.dead_code,
        language=Language.python,
        file=Path("src/b.py"),
        line=1,
        message="unused import",
    )
    extractor = MetricsExtractor()
    metrics = extractor.extract_from_scan_results(
        [
            _scan_result("ruff", findings=[finding]),
            _scan_result("coverage", metadata={"scalar_metrics": {"coverage_percent": 91.2}}),
        ]
    )
    categories = {metric.category for metric in metrics}
    assert ScoreCategory.dead_code in categories
    assert ScoreCategory.coverage in categories
    coverage_metric = next(metric for metric in metrics if metric.category == ScoreCategory.coverage)
    assert coverage_metric.scalar_name == "coverage_percent"


def test_metrics_extractor_supports_js_coverage_and_npm_audit() -> None:
    finding = Finding(
        tool="npm_audit",
        rule_id="NPM.AUDIT.GHSA-1",
        severity=Severity.high,
        category=Category.security,
        language=Language.javascript,
        file=Path("package.json"),
        line=1,
        message="vuln",
    )
    extractor = MetricsExtractor()
    metrics = extractor.extract_from_scan_results(
        [
            _scan_result("npm_audit", findings=[finding]),
            _scan_result("js_coverage", metadata={"scalar_metrics": {"coverage_percent": 76.0}}),
        ]
    )
    categories = {metric.category for metric in metrics}
    assert ScoreCategory.security in categories
    assert ScoreCategory.coverage in categories
