from __future__ import annotations

import json
from pathlib import Path

from codegauge.reporting import StaticSiteBuilder


def _seed_snapshot_reports(reports_dir: Path) -> None:
    scan_dir = reports_dir / "snap" / "scans" / "20260101T000000Z"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "summary.json").write_text(
        json.dumps(
            {
                "project": "snap",
                "scanner_count": 1,
                "successful_scanners": 1,
                "failed_scanners": 0,
                "finding_count": 2,
                "invalid_findings": 0,
                "invalid_paths": 0,
                "parse_failures": 0,
                "parser_missing": 0,
                "scanner_failures": 0,
                "duration_ms": 5,
                "project_metadata": {
                    "java": {"frameworks": ["spring_boot"], "module_count": 2},
                    "infrastructure": {
                        "detected": True,
                        "frameworks": ["containers", "terraform", "shell"],
                        "dockerfiles": ["Dockerfile"],
                        "compose_files": ["docker-compose.yml"],
                        "quadlets": [],
                        "traefik_configs": [],
                        "apache_configs": [],
                        "nginx_configs": ["nginx.conf"],
                        "terraform_files": ["main.tf"],
                        "shell_scripts": ["scripts/deploy.sh"],
                    },
                },
                "results": [
                    {
                        "scanner_name": "ruff",
                        "success": True,
                        "error_code": None,
                        "finding_count": 2,
                        "duration_ms": 5,
                    }
                ],
            }
        )
    )
    (scan_dir / "findings.json").write_text(
        json.dumps(
            [
                {"severity": "high", "file": "src/a.py"},
                {"severity": "low", "file": "src/b.py"},
            ]
        )
    )
    (scan_dir / "score.json").write_text(
        json.dumps(
            {
                "overall_score": 72.5,
                "grade": "C",
                "category_scores": [
                    {"category": "security", "score": 70.0, "finding_count": 1, "weight": 0.3, "summary": "x"}
                ],
                "finding_counts": {"security": 1},
                "scalar_metrics": {
                    "maintainability_index": 74.0,
                    "average_complexity": 8.2,
                    "worst_complexity": 19,
                    "maintainability_grade": "B",
                    "complexity_grade": "C",
                    "coverage_percent": 84.0,
                    "branch_coverage_percent": 72.0,
                    "duplication_percent": 8.0,
                    "avg_complexity": 6.3,
                    "class_count": 10,
                    "method_count": 80,
                },
                "measured_categories": ["security", "coverage", "maintainability", "complexity"],
                "dedupe": {
                    "total_findings": 3,
                    "suppressed_count": 1,
                    "net_findings": 2,
                    "suppressed_per_scanner": {"opengrep": 1},
                },
                "baseline": {
                    "gross_findings": 2,
                    "accepted_debt": 1,
                    "new_findings": 1,
                    "resolved_findings": 0,
                    "scored_findings": 1,
                    "accepted_entries": 5,
                    "expired_entries": 1,
                    "expiring_soon_entries": 2,
                    "missing_owner_entries": 1,
                },
                "warnings": [],
                "java_cache": {
                    "cached_modules": 2,
                    "cache_hits": 1,
                    "cache_misses": 1,
                    "hit_rate_percent": 50.0,
                    "miss_reason_counts": {"manifest_missing": 1},
                    "tools": [{"tool": "jacoco", "hits": 1, "misses": 1, "miss_reason_counts": {"manifest_missing": 1}}],
                    "last_cache_update": "2026-04-28T01:02:03Z",
                },
            }
        )
    )
    (scan_dir / "policy.json").write_text(
        json.dumps(
            {
                "status": "warn",
                "reasons": ["low_score"],
                "violations": [],
                "warnings": ["overall score below 80"],
                "summary": "warn",
            }
        )
    )


def test_html_snapshot_contains_expected_sections(tmp_path: Path) -> None:
    reports_dir = tmp_path / "reports"
    site_dir = tmp_path / "site"
    _seed_snapshot_reports(reports_dir)

    builder = StaticSiteBuilder(reports_root=reports_dir, site_root=site_dir)
    builder.build()

    index_html = (site_dir / "index.html").read_text()
    project_html = (site_dir / "projects" / "snap.html").read_text()

    assert "CodeGauge Leadership Summary" in index_html
    assert "Reason Codes" in index_html
    assert "low_score" in index_html
    assert "Executive Summary" in index_html
    assert "Project Count" in index_html
    assert "Worst Project" in index_html
    assert "Cache Hit Rate" in index_html
    assert "Python Cache Efficiency" in index_html
    assert "Java Cache Efficiency" in index_html
    assert "JavaScript Cache Efficiency" in index_html
    assert "Django Cache Efficiency" in index_html

    assert "Project: snap" in project_html
    assert "Frameworks:" in project_html
    assert "Module count:" in project_html
    assert "Overall score:" in project_html
    assert "Metric Cards" in project_html
    assert "Java Metrics" in project_html
    assert "Spring Posture" in project_html
    assert "Java Trend" in project_html
    assert "Java Cache" in project_html
    assert "Miss reasons:" in project_html
    assert "Dedupe" in project_html
    assert "Runs" in project_html
    assert "Local:" in project_html
    assert "UTC:" in project_html
    assert "Findings by Severity" in project_html
    assert "Top Files" in project_html
    assert "Scanner Status" in project_html
    assert "Historical Trend" in project_html
    assert "Maintainability Index" in project_html
    assert "Average Complexity" in project_html
    assert "Worst Complexity" in project_html
    assert "Accepted Debt" in project_html
    assert "New Debt" in project_html
    assert "Resolved Debt" in project_html
    assert "Duplicates Suppressed" in project_html
    assert "Baseline Governance" in project_html
    assert "Accepted Entries" in project_html
    assert "Expired Entries" in project_html
    assert "Infrastructure" in project_html
    assert "Container Hardening" in project_html
    assert "Reverse Proxy Posture" in project_html
    assert "IaC Safety" in project_html
    assert "../../reports/snap/scans/20260101T000000Z/summary.json" in project_html
