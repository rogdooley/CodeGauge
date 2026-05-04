from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from codegauge.cli import app


runner = CliRunner()


def _write_run(
    report_root: Path,
    project: str,
    run_id: str,
    score: float,
    grade: str,
    policy_status: str,
    reasons: list[str],
    *,
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
) -> None:
    run_dir = report_root / "projects" / project / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "project": project,
        "scanner_count": 1,
        "successful_scanners": 1,
        "failed_scanners": 0,
        "finding_count": critical + high + medium + low,
        "invalid_findings": 0,
        "invalid_paths": 0,
        "parse_failures": 0,
        "parser_missing": 0,
        "scanner_failures": 0,
        "duration_ms": 40.0,
        "results": [{"scanner_name": "ruff", "success": True, "error_code": None, "finding_count": 1, "duration_ms": 20.0}],
        "project_metadata": {
            "python_runtime": {"language": "python", "framework": "generic", "framework_confidence": 0.4}
        },
        "schema_version": "2.0.0",
    }
    findings = []
    findings.extend([{"severity": "critical", "file": "src/c.py"}] * critical)
    findings.extend([{"severity": "high", "file": "src/h.py"}] * high)
    findings.extend([{"severity": "medium", "file": "src/m.py"}] * medium)
    findings.extend([{"severity": "low", "file": "src/l.py"}] * low)
    score_payload = {
        "overall_score": score,
        "grade": grade,
        "category_scores": [],
        "finding_counts": {},
        "warnings": [],
    }
    policy_payload = {
        "status": policy_status,
        "reasons": reasons,
        "violations": [] if policy_status != "fail" else ["x"],
        "warnings": [] if policy_status == "pass" else ["w"],
        "summary": "policy",
    }
    manifest = {
        "project": project,
        "generated_at": "2026-04-29T00:00:00Z",
        "score": score,
        "grade": grade,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "report_path": str(run_dir / "report.html"),
        "schema_version": "2.0.0",
    }

    (run_dir / "summary.json").write_text(json.dumps(summary))
    (run_dir / "findings.json").write_text(json.dumps(findings))
    (run_dir / "score.json").write_text(json.dumps(score_payload))
    (run_dir / "policy.json").write_text(json.dumps(policy_payload))
    (run_dir / "run_manifest.json").write_text(json.dumps(manifest))
    (run_dir / "report.html").write_text("<html><body>report</body></html>")
    (run_dir / "action-plan.json").write_text(json.dumps({"schema_version": "1.0.0", "executive_summary": "x"}))
    (run_dir / "inventory.json").write_text(json.dumps({}))
    (run_dir / "policy-resolution.json").write_text(json.dumps({}))


def test_build_site_generates_portal_and_project_indexes(tmp_path: Path) -> None:
    project = tmp_path / "site-proj"
    project.mkdir()
    report_root = project / "CodeGauge"
    state_root = project / "state"
    (project / "pyproject.toml").write_text("[project]\nname='site-proj'\nversion='0.0.1'\n")
    (project / ".codegauge.toml").write_text(
        "\n".join(
            [
                f'report_root = "{report_root.as_posix()}"',
                f'state_root = "{state_root.as_posix()}"',
            ]
        )
    )

    _write_run(report_root, "alpha", "2026-04-29_010203", 85.0, "B", "pass", [], high=1, medium=2)
    _write_run(report_root, "alpha", "2026-04-30_010203", 90.0, "A", "pass", [], low=3)
    _write_run(report_root, "beta", "2026-04-29_010203", 55.0, "F", "fail", ["low_score"], critical=1, high=2)

    result = runner.invoke(app, ["build-site", str(project)])
    assert result.exit_code == 0
    assert "Built site for 2 projects" in result.stdout

    index = (report_root / "index.html").read_text()
    alpha = (report_root / "projects" / "alpha" / "index.html").read_text()
    beta = (report_root / "projects" / "beta" / "index.html").read_text()
    shared_css = report_root / "assets" / "report.css"
    shared_js = report_root / "assets" / "theme.js"

    assert "CodeGauge Report Portal" in index
    assert "Project Count" in index
    assert "Language Distribution" in index
    assert "python" in index
    assert "alpha" in index and "beta" in index
    assert "projects/alpha/index.html" in index
    assert "projects/beta/index.html" in index
    assert "Project: alpha" in alpha
    assert "Runs" in alpha
    assert "report.html" in alpha
    assert "details.html" in alpha
    assert "summary.json" in alpha
    assert "findings.json" in alpha
    assert "action-plan.json" in alpha
    assert "Project: beta" in beta
    assert (report_root / "projects" / "alpha" / "latest").exists()
    assert shared_css.exists()
    assert shared_js.exists()
    assert "assets/report.css" in index
    assert "assets/theme.js" in index


def test_scan_generates_portal_tree_with_runs_and_latest(tmp_path: Path) -> None:
    project = tmp_path / "scan_portal"
    project.mkdir()
    report_root = tmp_path / "CodeGauge"
    state_root = tmp_path / "state"
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / "a.py").write_text("x=1\n")
    (project / ".codegauge.toml").write_text(
        "\n".join(
            [
                f'report_root = "{report_root.as_posix()}"',
                f'state_root = "{state_root.as_posix()}"',
                'enabled_scanners = ["ruff"]',
            ]
        )
    )

    result = runner.invoke(app, ["scan", str(project), "--json"])
    assert result.exit_code == 0
    portal = report_root / "index.html"
    assert portal.exists()

    project_dir = report_root / "projects" / "scan_portal"
    assert (project_dir / "index.html").exists()
    runs = sorted([p for p in (project_dir / "runs").iterdir() if p.is_dir()])
    assert len(runs) == 1
    run_dir = runs[0]
    assert (run_dir / "summary.json").exists()
    assert (run_dir / "findings.json").exists()
    assert (run_dir / "run_manifest.json").exists()
    assert (run_dir / "report.html").exists()
    assert (run_dir / "details.html").exists()
    assert (run_dir / "action-plan.json").exists()
    assert (run_dir / "inventory.json").exists()
    assert (run_dir / "policy-resolution.json").exists()
    assert (project_dir / "latest").exists()

    run_report = (run_dir / "report.html").read_text()
    assert "href=\"details.html\"" in run_report
    run_details = (run_dir / "details.html").read_text()
    assert "href=\"summary.json\"" in run_details
    assert "href=\"findings.json\"" in run_details
    assert "href=\"action-plan.json\"" in run_details
    assert "Security Findings by Classification" in run_details
