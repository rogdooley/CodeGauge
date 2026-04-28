from __future__ import annotations

import json
from pathlib import Path

from codegauge.reporting import StaticSiteBuilder


def test_project_run_timestamps_include_local_and_utc(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    site = tmp_path / "site"
    scan_dir = reports / "proj" / "scans" / "20260427T223100Z"
    scan_dir.mkdir(parents=True)

    (scan_dir / "summary.json").write_text(json.dumps({"results": [], "scanner_count": 0, "successful_scanners": 0, "failed_scanners": 0, "finding_count": 0, "invalid_findings": 0, "invalid_paths": 0, "parse_failures": 0, "parser_missing": 0, "scanner_failures": 0, "project": "proj", "duration_ms": 1.0}))
    (scan_dir / "findings.json").write_text("[]")
    (scan_dir / "score.json").write_text(json.dumps({"overall_score": 87.0, "grade": "B", "category_scores": [], "finding_counts": {}, "warnings": []}))
    (scan_dir / "policy.json").write_text(json.dumps({"status": "pass", "reasons": [], "violations": [], "warnings": [], "summary": "ok"}))

    StaticSiteBuilder(reports_root=reports, site_root=site).build()

    html = (site / "projects" / "proj.html").read_text()
    assert "Local:" in html
    assert "UTC:" in html
    assert "title=" in html
    assert "summary.json" in html
