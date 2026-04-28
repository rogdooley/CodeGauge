from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from codegauge.baseline import BaselineDocument, BaselineEntry, BaselineService
from codegauge.domain.models import Category, Finding, Language, ScanResult, Severity
from codegauge.services.metrics import MetricsExtractor, finding_fingerprint
from codegauge.scoring.engine import CodeGaugeScoringEngine
from codegauge.scoring.models import ScoreCategory


def _scan_result(findings: list[Finding]) -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        scanner_name="ruff",
        started_at=now,
        completed_at=now,
        duration_ms=1.0,
        findings=findings,
        success=True,
        metadata={},
    )


def _finding(*, tool: str, rule_id: str, file: str, line: int, message: str) -> Finding:
    return Finding(
        tool=tool,
        rule_id=rule_id,
        severity=Severity.medium,
        category=Category.lint,
        language=Language.python,
        file=Path(file),
        line=line,
        message=message,
    )


def test_baseline_service_matches_and_excludes_accepted_findings_from_scoring() -> None:
    kept = _finding(tool="ruff", rule_id="E402", file="src/app.py", line=9, message="module level import")
    accepted = _finding(tool="ruff", rule_id="F401", file="src/app.py", line=3, message="unused import")
    accepted_fingerprint = finding_fingerprint(accepted, include_tool=True)
    baseline = BaselineDocument(
        entries=[
            BaselineEntry(
                fingerprint=accepted_fingerprint,
                accepted=True,
                note="known debt",
                owner="team-x",
                created_at=datetime.now(UTC),
            )
        ]
    )

    service = BaselineService()
    applied = service.apply([_scan_result([kept, accepted])], baseline)
    filtered = applied.filtered_results[0]
    assert len(filtered.findings) == 1
    assert filtered.findings[0].rule_id == "E402"
    assert applied.stats.gross_findings == 2
    assert applied.stats.accepted_debt == 1
    assert applied.stats.new_findings == 1
    assert applied.stats.scored_findings == 1
    assert applied.stats.resolved_findings == 0
    assert applied.stats.accepted_entries == 1
    assert applied.stats.expired_entries == 0
    assert applied.stats.expiring_soon_entries == 0
    assert applied.stats.missing_owner_entries == 0
    metrics = MetricsExtractor().extract_from_scan_results(applied.filtered_results)
    lint_metric = next(metric for metric in metrics if metric.category == ScoreCategory.lint)
    assert lint_metric.count == 1
    card = CodeGaugeScoringEngine().score(metrics)
    lint_score = next(entry for entry in card.category_scores if entry.category == ScoreCategory.lint)
    assert lint_score.finding_count == 1


def test_baseline_service_tracks_resolved_findings() -> None:
    stale_fingerprint = "ruff|lint|E111|src/legacy.py|12|deadbeef"
    baseline = BaselineDocument(
        entries=[
            BaselineEntry(
                fingerprint=stale_fingerprint,
                accepted=True,
                note="legacy",
                owner="team-x",
                created_at=datetime.now(UTC),
            )
        ]
    )

    service = BaselineService()
    applied = service.apply([_scan_result([])], baseline)
    assert applied.stats.gross_findings == 0
    assert applied.stats.accepted_debt == 0
    assert applied.stats.new_findings == 0
    assert applied.stats.resolved_findings == 1
    assert applied.stats.accepted_entries == 1


def test_baseline_expiration_prevents_match() -> None:
    finding = _finding(tool="ruff", rule_id="F401", file="src/a.py", line=1, message="unused")
    fingerprint = finding_fingerprint(finding, include_tool=True)
    expired_entry = BaselineEntry(
        fingerprint=fingerprint,
        accepted=True,
        created_at=datetime.now(UTC) - timedelta(days=30),
        expires_at=datetime.now(UTC) - timedelta(days=1),
    )
    baseline = BaselineDocument(entries=[expired_entry])

    service = BaselineService()
    applied = service.apply([_scan_result([finding])], baseline)
    assert len(applied.filtered_results[0].findings) == 1
    assert applied.stats.accepted_debt == 0
    assert applied.stats.new_findings == 1
    assert applied.stats.resolved_findings == 0
    assert applied.stats.expired_entries == 1


def test_baseline_governance_counts_missing_owner_and_expiring_soon() -> None:
    finding = _finding(tool="ruff", rule_id="F401", file="src/a.py", line=1, message="unused")
    fingerprint = finding_fingerprint(finding, include_tool=True)
    baseline = BaselineDocument(
        entries=[
            BaselineEntry(
                fingerprint=fingerprint,
                accepted=True,
                owner=None,
                created_at=datetime.now(UTC) - timedelta(days=10),
                expires_at=datetime.now(UTC) + timedelta(days=3),
            )
        ]
    )
    service = BaselineService(expiring_soon_days=7)
    applied = service.apply([_scan_result([finding])], baseline)
    assert applied.stats.accepted_entries == 1
    assert applied.stats.expiring_soon_entries == 1
    assert applied.stats.missing_owner_entries == 1


def test_baseline_service_loads_baseline_json_list_or_document(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    entry_payload = {
        "fingerprint": "ruff|lint|F401|src/a.py|1|abc",
        "accepted": True,
        "created_at": datetime.now(UTC).isoformat(),
    }
    (project / "baseline.json").write_text(json.dumps([entry_payload]))

    service = BaselineService()
    loaded_list = service.load(project)
    assert len(loaded_list.entries) == 1

    (project / "baseline.json").write_text(json.dumps({"entries": [entry_payload]}))
    loaded_obj = service.load(project)
    assert len(loaded_obj.entries) == 1
