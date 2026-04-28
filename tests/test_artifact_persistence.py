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
    reports_dir = project / "reports"
    site_dir = project / "site"
    (project / ".codegauge.toml").write_text(
        "\n".join(
            [
                f'reports_dir = "{reports_dir.as_posix()}"',
                f'site_dir = "{site_dir.as_posix()}"',
                'enabled_scanners = ["ruff"]',
            ]
        )
    )

    result = runner.invoke(app, ["scan", str(project), "--json"])
    assert result.exit_code == 0

    project_reports = reports_dir / "artifact-project"
    scans_root = project_reports / "scans"
    assert scans_root.exists()

    scan_dirs = sorted([path for path in scans_root.iterdir() if path.is_dir()])
    assert len(scan_dirs) == 1
    scan_dir = scan_dirs[0]

    for file_name in ["summary.json", "findings.json", "score.json", "policy.json"]:
        assert (scan_dir / file_name).exists()
    raw_files = list((scan_dir / "raw").glob("*.json"))
    assert raw_files

    latest = project_reports / "latest"
    assert latest.exists()
    assert (latest / "summary.json").exists()

    summary_payload = json.loads((scan_dir / "summary.json").read_text())
    policy_payload = json.loads((scan_dir / "policy.json").read_text())
    score_payload = json.loads((scan_dir / "score.json").read_text())

    assert summary_payload["project"] == "artifact-project"
    assert "score_card" in summary_payload
    assert "policy" in summary_payload
    assert "status" in policy_payload
    assert "overall_score" in score_payload
