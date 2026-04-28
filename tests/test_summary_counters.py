from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from codegauge.cli import _to_scan_summary
from codegauge.domain.models import Category, Finding, Language, ScanResult, Severity


def _finding(file_path: str) -> Finding:
    return Finding(
        tool="ruff",
        rule_id="F401",
        severity=Severity.low,
        category=Category.dead_code,
        language=Language.python,
        file=Path(file_path),
        line=1,
        column=1,
        message="unused import",
    )


def _scan_result(*, scanner_name: str, success: bool, error_code: str | None, finding_count: int, metadata: dict | None = None) -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        scanner_name=scanner_name,
        started_at=now,
        completed_at=now,
        duration_ms=1.0,
        findings=[_finding("src/a.py") for _ in range(finding_count)],
        success=success,
        error_code=error_code,
        error=None,
        metadata=metadata or {},
    )


def test_scan_summary_explicit_counters() -> None:
    summary = _to_scan_summary(
        "demo",
        12.5,
        [
            _scan_result(scanner_name="ruff", success=True, error_code=None, finding_count=2),
            _scan_result(scanner_name="pyright", success=False, error_code="scanner_timeout", finding_count=0),
            _scan_result(scanner_name="ruff", success=False, error_code="scanner_output_invalid", finding_count=0),
            _scan_result(scanner_name="opengrep", success=False, error_code="scanner_parser_missing", finding_count=0),
            _scan_result(
                scanner_name="bandit",
                success=False,
                error_code="finding_path_invalid",
                finding_count=0,
                metadata={"invalid_finding_count": 2},
            ),
        ],
        verbose=False,
    )

    assert summary.scanner_count == 5
    assert summary.successful_scanners == 1
    assert summary.failed_scanners == 4
    assert summary.finding_count == 2
    assert summary.invalid_findings == 2
    assert summary.invalid_paths == 2
    assert summary.parse_failures == 1
    assert summary.parser_missing == 1
    assert summary.scanner_failures == 1
