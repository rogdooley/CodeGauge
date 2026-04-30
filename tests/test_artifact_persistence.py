from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from codegauge.cli import app


runner = CliRunner()


def test_scan_persists_artifacts(tmp_path: Path) -> None:
    project = tmp_path / "artifact-project"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='artifact-project'\nversion='0.0.1'\n")
    report_root = project / "CodeGauge"
    state_root = project / "state"
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

    project_reports = report_root / "projects" / "artifact-project"
    runs_root = project_reports / "runs"
    assert runs_root.exists()

    scan_dirs = sorted([path for path in runs_root.iterdir() if path.is_dir()])
    assert len(scan_dirs) == 1
    scan_dir = scan_dirs[0]

    for file_name in [
        "summary.json",
        "findings.json",
        "score.json",
        "policy.json",
        "run_manifest.json",
        "action-plan.json",
        "inventory.json",
        "policy-resolution.json",
        "report.html",
        "details.html",
    ]:
        assert (scan_dir / file_name).exists()
    raw_files = list((scan_dir / "raw").glob("*.json"))
    assert raw_files

    latest = project_reports / "latest"
    assert latest.exists()
    assert (latest / "summary.json").exists()
    assert (project_reports / "latest_manifest.json").exists()
    assert (report_root / "index.html").exists()
    assert (report_root / "projects" / "artifact-project" / "index.html").exists()

    summary_payload = json.loads((scan_dir / "summary.json").read_text())
    findings_payload = json.loads((scan_dir / "findings.json").read_text())
    policy_payload = json.loads((scan_dir / "policy.json").read_text())
    score_payload = json.loads((scan_dir / "score.json").read_text())
    action_plan_payload = json.loads((scan_dir / "action-plan.json").read_text())

    assert summary_payload["project"] == "artifact-project"
    assert "score_card" in summary_payload
    assert "policy" in summary_payload
    assert "inventory" in summary_payload
    assert "policy_resolution" in summary_payload
    assert "parser_summary" in summary_payload
    assert "security_summary" in summary_payload
    assert "classifier" in summary_payload
    assert "report_sha256" in summary_payload
    assert summary_payload["classifier"]["name"] == "security_classifier"
    assert "status" in policy_payload
    assert "overall_score" in score_payload
    for section in (
        "top_recommendations",
        "quick_wins",
        "architectural_concerns",
        "security_concerns",
        "systemic_issues",
    ):
        assert section in action_plan_payload
        assert isinstance(action_plan_payload[section], list)
        for item in action_plan_payload.get(section, []):
            assert "_score" not in item
    assert action_plan_payload["schema_version"] == "1.0.0"
    assert action_plan_payload["recommendation_engine_version"] == "1"
    assert action_plan_payload["ruleset_version"] == "1"
    assert "generated_from" in action_plan_payload
    assert set(action_plan_payload["generated_from"].keys()) == {"findings_count", "clusters_count", "source_schema_version"}
    if findings_payload:
        first = findings_payload[0]
        for required in (
            "tool",
            "rule_id",
            "native_severity",
            "severity",
            "security_class",
            "security_context",
            "security_impact",
            "score_weight",
            "classification_reason",
            "classification_rule_id",
            "ownership",
            "ownership_confidence",
            "fingerprint",
        ):
            assert required in first
