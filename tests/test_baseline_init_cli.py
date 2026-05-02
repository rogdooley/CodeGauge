from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from codegauge.cli import app
from codegauge.domain.models import Category, Finding, Language, Project, ScanResult, Severity


runner = CliRunner()


def _scan_result(scanner_name: str, finding: Finding) -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        scanner_name=scanner_name,
        started_at=now,
        completed_at=now,
        duration_ms=1.0,
        findings=[finding],
        success=True,
        metadata={},
    )


def _services(project_path: Path):
    class _Orchestrator:
        @staticmethod
        def run(_project: Project):
            shared = Finding(
                tool="ruff",
                rule_id="F401",
                severity=Severity.low,
                category=Category.dead_code,
                language=Language.python,
                file=Path("src/app.py"),
                line=3,
                message="unused import os",
            )
            duplicate = shared.model_copy(update={"tool": "vulture"})
            return [
                _scan_result("ruff", shared),
                _scan_result("vulture", duplicate),
            ]

    class _Services:
        project = Project(name=project_path.name, path=project_path, language_hints=[Language.python])
        orchestrator = _Orchestrator()

    return _Services()


def test_baseline_init_dry_run_shows_count_and_samples(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    monkeypatch.setattr("codegauge.cli.build_scan_services_with_config", lambda _p, _c: _services(project))

    result = runner.invoke(
        app,
        ["baseline", "init", str(project), "--dry-run", "--owner", "team-a", "--note", "initial debt"],
    )
    assert result.exit_code == 0
    assert "Dry run: yes" in result.stdout
    assert "Entries to generate: 1" in result.stdout
    assert "Suppressed duplicates excluded: 1" in result.stdout
    assert not (project / "baseline.json").exists()


def test_baseline_init_refuses_overwrite_without_force(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj2"
    project.mkdir()
    monkeypatch.setattr("codegauge.cli.build_scan_services_with_config", lambda _p, _c: _services(project))

    first = runner.invoke(app, ["baseline", "init", str(project), "--owner", "team-a"])
    assert first.exit_code == 0
    baseline_path = project / "baseline.json"
    assert baseline_path.exists()

    second = runner.invoke(app, ["baseline", "init", str(project)])
    assert second.exit_code == 3
    assert "Refusing to overwrite existing baseline file" in second.stderr


def test_baseline_init_force_overwrites_and_sets_expiration(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj3"
    project.mkdir()
    monkeypatch.setattr("codegauge.cli.build_scan_services_with_config", lambda _p, _c: _services(project))

    first = runner.invoke(app, ["baseline", "init", str(project), "--owner", "team-a"])
    assert first.exit_code == 0
    second = runner.invoke(
        app,
        ["baseline", "init", str(project), "--force", "--owner", "team-b", "--expires-days", "30"],
    )
    assert second.exit_code == 0

    payload = json.loads((project / "baseline.json").read_text())
    assert len(payload["entries"]) == 1
    entry = payload["entries"][0]
    assert entry["owner"] == "team-b"
    assert entry["expires_at"] is not None
