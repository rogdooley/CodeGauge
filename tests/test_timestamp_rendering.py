from __future__ import annotations

import json
from pathlib import Path

from codegauge.reporting import StaticSiteBuilder


def test_project_run_timestamps_include_local_and_raw_generated_time(tmp_path: Path) -> None:
    reports = tmp_path / "CodeGauge"
    site = tmp_path / "CodeGaugeSite"
    run_dir = reports / "projects" / "proj" / "runs" / "2026-04-27_223100"
    run_dir.mkdir(parents=True)

    (run_dir / "summary.json").write_text(json.dumps({"results": [], "scanner_count": 0, "successful_scanners": 0, "failed_scanners": 0, "finding_count": 0, "invalid_findings": 0, "invalid_paths": 0, "parse_failures": 0, "parser_missing": 0, "scanner_failures": 0, "project": "proj", "duration_ms": 1.0, "schema_version": "2.0.0"}))
    (run_dir / "findings.json").write_text("[]")
    (run_dir / "score.json").write_text(json.dumps({"overall_score": 87.0, "grade": "B", "category_scores": [], "finding_counts": {}, "warnings": []}))
    (run_dir / "policy.json").write_text(json.dumps({"status": "pass", "reasons": [], "violations": [], "warnings": [], "summary": "ok"}))
    (run_dir / "run_manifest.json").write_text(
        json.dumps(
            {
                "project": "proj",
                "generated_at": "2026-04-27T22:31:00Z",
                "score": 87.0,
                "grade": "B",
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "report_path": str(run_dir / "report.html"),
                "schema_version": "2.0.0",
            }
        )
    )
    (run_dir / "report.html").write_text("<html></html>")

    StaticSiteBuilder(reports_root=reports, site_root=site).build()

    html = (site / "projects" / "proj" / "index.html").read_text()
    assert "title=" in html
    assert "summary.json" in html
    assert "2026-04-27T22:31:00Z" in html
