from __future__ import annotations

from codegauge.domain.models import ScanResultSummary, ScanSummary


def test_scan_summary_model_serialization() -> None:
    summary = ScanSummary(
        project="demo",
        scanner_count=2,
        successful_scanners=1,
        failed_scanners=1,
        finding_count=3,
        invalid_findings=1,
        invalid_paths=1,
        parse_failures=1,
        parser_missing=1,
        scanner_failures=0,
        score_card={"overall_score": 88.1, "grade": "B"},
        policy={"status": "warn"},
        duration_ms=42.5,
        results=[
            ScanResultSummary(
                scanner_name="ruff",
                success=True,
                error_code=None,
                finding_count=3,
                duration_ms=12.5,
            ),
            ScanResultSummary(
                scanner_name="bandit",
                success=False,
                error_code="scanner_binary_missing",
                finding_count=0,
                duration_ms=0.1,
                command=["bandit", "-r", "."],
                exit_code=None,
            ),
        ],
    )
    payload = summary.model_dump(mode="json", exclude_none=True)
    assert payload["project"] == "demo"
    assert payload["scanner_count"] == 2
    assert payload["invalid_findings"] == 1
    assert payload["invalid_paths"] == 1
    assert payload["parse_failures"] == 1
    assert payload["parser_missing"] == 1
    assert payload["scanner_failures"] == 0
    assert payload["score_card"]["grade"] == "B"
    assert payload["policy"]["status"] == "warn"
    assert payload["results"][0]["scanner_name"] == "ruff"
    assert payload["results"][1]["error_code"] == "scanner_binary_missing"
