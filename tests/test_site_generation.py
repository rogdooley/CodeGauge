from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from codegauge.cli import app


runner = CliRunner()


def _write_scan(
    root: Path,
    project: str,
    scan_id: str,
    score: float,
    grade: str,
    policy_status: str,
    reasons: list[str],
    *,
    scalar_metrics: dict | None = None,
    finding_counts: dict | None = None,
    dedupe: dict | None = None,
    baseline: dict | None = None,
    project_metadata: dict | None = None,
) -> None:
    scan_dir = root / project / "scans" / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "project": project,
        "scanner_count": 2,
        "successful_scanners": 2,
        "failed_scanners": 0,
        "finding_count": 3,
        "invalid_findings": 0,
        "invalid_paths": 0,
        "parse_failures": 0,
        "parser_missing": 0,
        "scanner_failures": 0,
        "duration_ms": 40.0,
        "project_metadata": project_metadata or {},
        "results": [
            {"scanner_name": "ruff", "success": True, "error_code": None, "finding_count": 2, "duration_ms": 20.0},
            {"scanner_name": "bandit", "success": True, "error_code": None, "finding_count": 1, "duration_ms": 20.0},
        ],
    }
    findings = [
        {"severity": "high", "file": "src/app.py"},
        {"severity": "low", "file": "src/app.py"},
        {"severity": "medium", "file": "src/core.py"},
    ]
    score_payload = {
        "overall_score": score,
        "grade": grade,
        "category_scores": [
            {"category": "security", "score": score, "finding_count": 1, "weight": 0.3, "summary": "s"}
        ],
        "finding_counts": finding_counts or {"security": 1},
        "scalar_metrics": scalar_metrics or {},
        "measured_categories": sorted((finding_counts or {"security": 1}).keys()),
        "dedupe": dedupe or {"total_findings": 3, "suppressed_count": 0, "net_findings": 3, "suppressed_per_scanner": {}},
        "baseline": baseline
        or {
            "gross_findings": 3,
            "accepted_debt": 0,
            "new_findings": 3,
            "resolved_findings": 0,
            "scored_findings": 3,
            "accepted_entries": 0,
            "expired_entries": 0,
            "expiring_soon_entries": 0,
            "missing_owner_entries": 0,
        },
        "warnings": [],
        "java_cache": {
            "cached_modules": 3,
            "cache_hits": 2,
            "cache_misses": 1,
            "hit_rate_percent": 66.67,
            "miss_reason_counts": {"manifest_missing": 1},
            "tools": [{"tool": "spotbugs", "hits": 2, "misses": 1, "miss_reason_counts": {"manifest_missing": 1}}],
            "last_cache_update": "2026-04-28T01:02:03Z",
        },
    }
    policy_payload = {
        "status": policy_status,
        "reasons": reasons,
        "violations": [] if policy_status != "fail" else ["x"],
        "warnings": [] if policy_status == "pass" else ["w"],
        "summary": "policy",
    }
    (scan_dir / "summary.json").write_text(json.dumps(summary))
    (scan_dir / "findings.json").write_text(json.dumps(findings))
    (scan_dir / "score.json").write_text(json.dumps(score_payload))
    (scan_dir / "policy.json").write_text(json.dumps(policy_payload))


def test_build_site_generates_index_and_project_pages(tmp_path: Path) -> None:
    project = tmp_path / "site-proj"
    project.mkdir()
    reports_dir = project / "reports"
    site_dir = project / "site"
    (project / "pyproject.toml").write_text("[project]\nname='site-proj'\nversion='0.0.1'\n")
    (project / ".codegauge.toml").write_text(
        "\n".join(
            [
                f'reports_dir = "{reports_dir.as_posix()}"',
                f'site_dir = "{site_dir.as_posix()}"',
                'enabled_scanners = ["ruff"]',
            ]
        )
    )

    _write_scan(reports_dir, "alpha", "20260101T000000Z", 80.0, "B", "warn", ["low_score"])
    _write_scan(
        reports_dir,
        "alpha",
        "20260102T000000Z",
        85.0,
        "B",
        "pass",
        [],
        scalar_metrics={
            "coverage_percent": 84,
            "branch_coverage_percent": 76,
            "duplication_percent": 3.2,
            "maintainability_grade": "B",
            "maintainability_index": 74.0,
            "average_complexity": 8.2,
            "worst_complexity": 19,
            "complexity_grade": "C",
        },
        finding_counts={"dead_code": 12, "security": 0},
        dedupe={
            "total_findings": 15,
            "suppressed_count": 3,
            "net_findings": 12,
            "suppressed_per_scanner": {"vulture": 2, "opengrep": 1},
        },
        baseline={
            "gross_findings": 12,
            "accepted_debt": 4,
            "new_findings": 8,
            "resolved_findings": 2,
            "scored_findings": 8,
            "accepted_entries": 9,
            "expired_entries": 1,
            "expiring_soon_entries": 2,
            "missing_owner_entries": 1,
        },
        project_metadata={
            "java": {
                "frameworks": ["spring", "spring_boot"],
                "module_count": 3,
            }
        },
    )
    _write_scan(reports_dir, "beta", "20260101T000000Z", 55.0, "F", "fail", ["scanner_failure", "low_score"])
    _write_scan(reports_dir, "gamma", "20260101T000000Z", 62.0, "D", "warn", ["low_score"])

    django_scan_dir = reports_dir / "delta" / "scans" / "20260101T000000Z"
    django_scan_dir.mkdir(parents=True, exist_ok=True)
    (django_scan_dir / "summary.json").write_text(
        json.dumps(
            {
                "project": "delta",
                "scanner_count": 2,
                "successful_scanners": 2,
                "failed_scanners": 0,
                "finding_count": 2,
                "invalid_findings": 0,
                "invalid_paths": 0,
                "parse_failures": 0,
                "parser_missing": 0,
                "scanner_failures": 0,
                "duration_ms": 20.0,
                "project_metadata": {
                    "django": {
                        "detected": True,
                        "drf": True,
                        "channels": True,
                        "template_count": 4,
                    }
                },
                "results": [
                    {
                        "scanner_name": "django_check_deploy",
                        "success": True,
                        "error_code": None,
                        "finding_count": 1,
                        "duration_ms": 10.0,
                    }
                ],
            }
        )
    )
    (django_scan_dir / "findings.json").write_text(json.dumps([{"severity": "high", "file": "manage.py"}]))
    (django_scan_dir / "score.json").write_text(
        json.dumps(
            {
                "overall_score": 78.0,
                "grade": "C",
                "category_scores": [
                    {"category": "security", "score": 78.0, "finding_count": 2, "weight": 0.3, "summary": "s"}
                ],
                "finding_counts": {"security": 2},
                "scalar_metrics": {},
                "measured_categories": ["security"],
                "dedupe": {"total_findings": 2, "suppressed_count": 0, "net_findings": 2, "suppressed_per_scanner": {}},
                "baseline": {
                    "gross_findings": 2,
                    "accepted_debt": 0,
                    "new_findings": 2,
                    "resolved_findings": 0,
                    "scored_findings": 2,
                    "accepted_entries": 0,
                    "expired_entries": 0,
                    "expiring_soon_entries": 0,
                    "missing_owner_entries": 0,
                },
                "warnings": [],
                "java_cache": {"cache_hits": 0, "cache_misses": 0},
            }
        )
    )
    (django_scan_dir / "policy.json").write_text(
        json.dumps({"status": "warn", "reasons": ["low_score"], "violations": [], "warnings": ["x"], "summary": "warn"})
    )

    js_scan_dir = reports_dir / "epsilon" / "scans" / "20260101T000000Z"
    js_scan_dir.mkdir(parents=True, exist_ok=True)
    (js_scan_dir / "summary.json").write_text(
        json.dumps(
            {
                "project": "epsilon",
                "scanner_count": 2,
                "successful_scanners": 2,
                "failed_scanners": 0,
                "finding_count": 1,
                "invalid_findings": 0,
                "invalid_paths": 0,
                "parse_failures": 0,
                "parser_missing": 0,
                "scanner_failures": 0,
                "duration_ms": 10.0,
                "project_metadata": {
                    "typescript": {
                        "frameworks": ["react", "nextjs"],
                        "package_manager": "npm",
                        "dependency_count": 42,
                    }
                },
                "results": [
                    {"scanner_name": "eslint", "success": True, "error_code": None, "finding_count": 1, "duration_ms": 10.0}
                ],
            }
        )
    )
    (js_scan_dir / "findings.json").write_text(json.dumps([{"severity": "medium", "file": "src/app.ts"}]))
    (js_scan_dir / "score.json").write_text(
        json.dumps(
            {
                "overall_score": 88.0,
                "grade": "B",
                "category_scores": [
                    {"category": "lint", "score": 88.0, "finding_count": 1, "weight": 0.3, "summary": "s"}
                ],
                "finding_counts": {"lint": 1},
                "scalar_metrics": {},
                "measured_categories": ["lint"],
                "dedupe": {"total_findings": 1, "suppressed_count": 0, "net_findings": 1, "suppressed_per_scanner": {}},
                "baseline": {
                    "gross_findings": 1,
                    "accepted_debt": 0,
                    "new_findings": 1,
                    "resolved_findings": 0,
                    "scored_findings": 1,
                    "accepted_entries": 0,
                    "expired_entries": 0,
                    "expiring_soon_entries": 0,
                    "missing_owner_entries": 0,
                },
                "warnings": [],
                "java_cache": {"cache_hits": 0, "cache_misses": 0},
            }
        )
    )
    (js_scan_dir / "policy.json").write_text(
        json.dumps({"status": "pass", "reasons": [], "violations": [], "warnings": [], "summary": "pass"})
    )

    infra_scan_dir = reports_dir / "zeta" / "scans" / "20260101T000000Z"
    infra_scan_dir.mkdir(parents=True, exist_ok=True)
    (infra_scan_dir / "summary.json").write_text(
        json.dumps(
            {
                "project": "zeta",
                "scanner_count": 2,
                "successful_scanners": 2,
                "failed_scanners": 0,
                "finding_count": 2,
                "invalid_findings": 0,
                "invalid_paths": 0,
                "parse_failures": 0,
                "parser_missing": 0,
                "scanner_failures": 0,
                "duration_ms": 12.0,
                "project_metadata": {
                    "infrastructure": {
                        "detected": True,
                        "frameworks": ["containers", "reverse_proxy", "terraform", "shell"],
                        "dockerfiles": ["Dockerfile"],
                        "compose_files": ["docker-compose.yml"],
                        "quadlets": ["app.container"],
                        "traefik_configs": [],
                        "apache_configs": [],
                        "nginx_configs": ["nginx.conf"],
                        "terraform_files": ["main.tf"],
                        "shell_scripts": ["scripts/deploy.sh"],
                    }
                },
                "results": [
                    {
                        "scanner_name": "terraform_scan",
                        "success": True,
                        "error_code": None,
                        "finding_count": 1,
                        "duration_ms": 6.0,
                    }
                ],
            }
        )
    )
    (infra_scan_dir / "findings.json").write_text(json.dumps([{"severity": "high", "file": "main.tf"}]))
    (infra_scan_dir / "score.json").write_text(
        json.dumps(
            {
                "overall_score": 69.0,
                "grade": "D",
                "category_scores": [
                    {"category": "security", "score": 69.0, "finding_count": 2, "weight": 0.3, "summary": "s"}
                ],
                "finding_counts": {"security": 2},
                "scalar_metrics": {},
                "measured_categories": ["security"],
                "dedupe": {"total_findings": 2, "suppressed_count": 0, "net_findings": 2, "suppressed_per_scanner": {}},
                "baseline": {
                    "gross_findings": 2,
                    "accepted_debt": 0,
                    "new_findings": 2,
                    "resolved_findings": 0,
                    "scored_findings": 2,
                    "accepted_entries": 0,
                    "expired_entries": 0,
                    "expiring_soon_entries": 0,
                    "missing_owner_entries": 0,
                },
                "warnings": [],
                "java_cache": {"cache_hits": 0, "cache_misses": 0},
            }
        )
    )
    (infra_scan_dir / "policy.json").write_text(
        json.dumps({"status": "warn", "reasons": ["low_score"], "violations": [], "warnings": ["x"], "summary": "warn"})
    )

    result = runner.invoke(app, ["build-site", str(project)])
    assert result.exit_code == 0
    assert "Built site for 6 projects" in result.stdout

    index = (site_dir / "index.html").read_text()
    alpha = (site_dir / "projects" / "alpha.html").read_text()
    beta = (site_dir / "projects" / "beta.html").read_text()
    gamma = (site_dir / "projects" / "gamma.html").read_text()

    assert "CodeGauge Leadership Summary" in index
    assert "alpha" in index and "beta" in index and "gamma" in index
    assert "+5.00" in index
    assert "Project Count" in index
    assert "PASS / WARN / FAIL" in index
    assert "Average Score" in index
    assert "Worst Project" in index
    assert "Most Improved Project" in index
    assert "Cache Hits" in index
    assert "Cache Misses" in index
    assert "Cache Hit Rate" in index
    assert "Python Cache Efficiency" in index
    assert "Java Cache Efficiency" in index
    assert "JavaScript Cache Efficiency" in index
    assert "Django Cache Efficiency" in index
    order = re.findall(r'<td>\s*<a href="projects/(.+?)\.html">', index, flags=re.S)
    assert order[:3] == ["beta", "gamma", "zeta"]
    assert set(order) == {"alpha", "beta", "gamma", "delta", "epsilon", "zeta"}
    assert "Project: alpha" in alpha
    assert "Metric Cards" in alpha
    assert "Coverage" in alpha
    assert "Maintainability" in alpha
    assert "Complexity" in alpha
    assert "Dead code" in alpha
    assert "84%" in alpha
    assert ">B<" in alpha
    assert ">C<" in alpha
    assert "12 findings" in alpha
    assert "Score Breakdown" in alpha
    assert "Runs" in alpha
    assert "Local:" in alpha
    assert "UTC:" in alpha
    assert "Dedupe" in alpha
    assert "Total findings:" in alpha
    assert "Suppressed duplicates:" in alpha
    assert "Net scored findings:" in alpha
    assert "Accepted debt:" in alpha
    assert "New debt:" in alpha
    assert "Resolved debt:" in alpha
    assert "Baseline Governance" in alpha
    assert "Accepted Entries" in alpha
    assert "Expired Entries" in alpha
    assert "Expiring Soon" in alpha
    assert "Missing Owner" in alpha
    assert "Maintainability Index" in alpha
    assert "Average Complexity" in alpha
    assert "Worst Complexity" in alpha
    assert "Duplicates Suppressed" in alpha
    assert "Accepted Debt" in alpha
    assert "New Debt" in alpha
    assert "Resolved Debt" in alpha
    assert "74.00" in alpha
    assert "8.20" in alpha
    assert "19" in alpha
    assert "summary.json" in alpha
    assert "findings.json" in alpha
    assert "score.json" in alpha
    assert "policy.json" in alpha
    assert "raw/" in alpha
    assert "../../reports/alpha/scans/20260102T000000Z/summary.json" in alpha
    assert "Project: beta" in beta
    assert "Policy" in beta
    assert "n/a" in beta
    assert "Project: gamma" in gamma
    assert "Frameworks:" in alpha
    assert "spring_boot" in alpha
    assert "Module count:" in alpha
    assert "Java Metrics" in alpha
    assert "Branch Coverage" in alpha
    assert "Spring Posture" in alpha
    assert "Java Trend" in alpha
    assert "Java Cache" in alpha
    assert "Cached modules:" in alpha
    assert "Cache hits:" in alpha
    assert "Cache misses:" in alpha
    assert "Miss reasons:" in alpha
    delta = (site_dir / "projects" / "delta.html").read_text()
    epsilon = (site_dir / "projects" / "epsilon.html").read_text()
    zeta = (site_dir / "projects" / "zeta.html").read_text()
    assert "Framework Cards" in delta
    assert "Django" in delta
    assert "DRF" in delta
    assert "Channels" in delta
    assert "Framework Cards" in epsilon
    assert "JS/TS Frameworks" in epsilon
    assert "react, nextjs" in epsilon
    assert "Package manager" in epsilon
    assert "Infrastructure" in zeta
    assert "Container Hardening" in zeta
    assert "Reverse Proxy Posture" in zeta
    assert "Infrastructure Exposure" in zeta
    assert "Secrets Hygiene" in zeta
    assert "Runtime Isolation" in zeta
    assert "IaC Safety" in zeta
    assert "Shell Hygiene" in zeta
    assert "Coverage" in alpha
    assert "Branch" in alpha
    assert "Duplication" in alpha
