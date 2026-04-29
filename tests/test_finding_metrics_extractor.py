from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from codegauge.domain.models import Category, Finding, Language, ScanResult, Severity
from codegauge.scoring.models import ScoreCategory
from codegauge.services.metrics import MetricsExtractor


def _finding(*, tool: str, category: Category, severity: Severity) -> Finding:
    return Finding(
        tool=tool,
        rule_id="X1",
        severity=severity,
        category=category,
        language=Language.python,
        file=Path("src/example.py"),
        line=1,
        column=1,
        message="m",
    )


def _result(scanner_name: str, findings: list[Finding], success: bool = True) -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        scanner_name=scanner_name,
        started_at=now,
        completed_at=now,
        duration_ms=3.0,
        findings=findings,
        success=success,
        error_code=None if success else "scanner_nonzero_exit",
        error=None,
        metadata={},
    )


def test_extract_from_findings_aggregates_supported_source() -> None:
    extractor = MetricsExtractor()
    findings = [
        _finding(tool="ruff", category=Category.lint, severity=Severity.low),
        _finding(tool="ruff", category=Category.lint, severity=Severity.low),
        _finding(tool="ruff", category=Category.dead_code, severity=Severity.medium),
    ]

    metrics = extractor.extract_from_scan_results([_result("ruff", findings)])
    assert len(metrics) == 2

    lint_metric = next(metric for metric in metrics if metric.category == ScoreCategory.lint)
    dead_code_metric = next(metric for metric in metrics if metric.category == ScoreCategory.dead_code)

    assert lint_metric.count == 2
    assert lint_metric.source == "ruff"
    assert dead_code_metric.count == 1


def test_extract_from_findings_uses_generic_fallback_for_unsupported_source() -> None:
    extractor = MetricsExtractor()
    findings = [_finding(tool="pyright", category=Category.typing, severity=Severity.high)]
    metrics = extractor.extract_from_scan_results([_result("pyright", findings)])
    assert len(metrics) == 1
    assert metrics[0].category == ScoreCategory.typing
    assert metrics[0].severity == Severity.high
    assert metrics[0].count == 1
    assert metrics[0].source == "pyright"


def test_extract_from_scan_results_uses_generic_fallback_and_skips_failed_scanners() -> None:
    extractor = MetricsExtractor()
    results = [
        _result("ruff", [_finding(tool="ruff", category=Category.maintainability, severity=Severity.medium)]),
        _result("bandit", [_finding(tool="bandit", category=Category.security, severity=Severity.high)]),
        _result("pyright", [_finding(tool="pyright", category=Category.typing, severity=Severity.high)]),
        _result("bandit", [_finding(tool="bandit", category=Category.security, severity=Severity.high)], success=False),
    ]

    metrics = extractor.extract_from_scan_results(results, dedupe=False)
    assert len(metrics) == 3
    categories = {metric.category for metric in metrics}
    assert categories == {ScoreCategory.maintainability, ScoreCategory.security, ScoreCategory.typing}
