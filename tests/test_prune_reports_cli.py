from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from codegauge.cli import app


runner = CliRunner()


def _seed_scan_dirs(reports_dir: Path, project: str, scan_ids: list[str]) -> None:
    for scan_id in scan_ids:
        scan_dir = reports_dir / project / "scans" / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)


def test_prune_reports_requires_exactly_one_mode(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    result_none = runner.invoke(app, ["prune-reports", str(project)])
    assert result_none.exit_code == 3
    assert "Specify exactly one retention mode" in result_none.stderr

    result_both = runner.invoke(app, ["prune-reports", str(project), "--keep", "30", "--days", "180"])
    assert result_both.exit_code == 3
    assert "Specify exactly one retention mode" in result_both.stderr


def test_prune_reports_keep_and_dry_run(tmp_path: Path) -> None:
    project = tmp_path / "repo2"
    project.mkdir()
    reports_dir = project / "reports"
    (project / ".codegauge.toml").write_text(f'reports_dir = "{reports_dir.as_posix()}"\n')

    _seed_scan_dirs(reports_dir, "alpha", ["20240101T000000Z", "20240102T000000Z", "20240103T000000Z"])

    dry_result = runner.invoke(app, ["prune-reports", str(project), "--keep", "2", "--dry-run"])
    assert dry_result.exit_code == 0
    assert "would_remove=1" in dry_result.stdout
    assert "Dry run: yes" in dry_result.stdout
    assert "Project: alpha" in dry_result.stdout
    assert "Would remove: 1 scans" in dry_result.stdout
    assert "- 20240101T000000Z" in dry_result.stdout
    assert "Total scans selected: 1" in dry_result.stdout
    assert "Projects affected: 1" in dry_result.stdout
    assert "latest preserved:" in dry_result.stdout
    assert len(list((reports_dir / "alpha" / "scans").iterdir())) == 3

    apply_result = runner.invoke(app, ["prune-reports", str(project), "--keep", "2"])
    assert apply_result.exit_code == 0
    assert "removed=1" in apply_result.stdout
    assert "latest preserved:" in apply_result.stdout
    assert len(list((reports_dir / "alpha" / "scans").iterdir())) == 2


def test_prune_reports_days(tmp_path: Path) -> None:
    project = tmp_path / "repo3"
    project.mkdir()
    reports_dir = project / "reports"
    (project / ".codegauge.toml").write_text(f'reports_dir = "{reports_dir.as_posix()}"\n')

    _seed_scan_dirs(reports_dir, "alpha", ["20200101T000000Z", "20990101T000000Z"])

    dry_result = runner.invoke(app, ["prune-reports", str(project), "--days", "365", "--dry-run"])
    assert dry_result.exit_code == 0
    assert "Project: alpha" in dry_result.stdout
    assert "- 20200101T000000Z" in dry_result.stdout
    assert "Total scans selected: 1" in dry_result.stdout
    assert "Projects affected: 1" in dry_result.stdout

    result = runner.invoke(app, ["prune-reports", str(project), "--days", "365"])
    assert result.exit_code == 0
    assert "removed=1" in result.stdout
    assert "latest preserved:" in result.stdout
    remaining = [path.name for path in (reports_dir / "alpha" / "scans").iterdir()]
    assert "20990101T000000Z" in remaining
    assert "20200101T000000Z" not in remaining


def test_prune_reports_project_filter(tmp_path: Path) -> None:
    project = tmp_path / "repo4"
    project.mkdir()
    reports_dir = project / "reports"
    (project / ".codegauge.toml").write_text(f'reports_dir = "{reports_dir.as_posix()}"\n')
    _seed_scan_dirs(reports_dir, "alpha", ["20240101T000000Z", "20240102T000000Z"])
    _seed_scan_dirs(reports_dir, "beta", ["20240101T000000Z", "20240102T000000Z"])

    result = runner.invoke(app, ["prune-reports", str(project), "--keep", "1", "--project", "alpha", "--dry-run"])
    assert result.exit_code == 0
    assert "Project: alpha" in result.stdout
    assert "Project: beta" not in result.stdout


def test_prune_reports_project_filter_accepts_multiple_projects(tmp_path: Path) -> None:
    project = tmp_path / "repo5"
    project.mkdir()
    reports_dir = project / "reports"
    (project / ".codegauge.toml").write_text(f'reports_dir = "{reports_dir.as_posix()}"\n')
    _seed_scan_dirs(reports_dir, "alpha", ["20240101T000000Z", "20240102T000000Z"])
    _seed_scan_dirs(reports_dir, "beta", ["20240101T000000Z", "20240102T000000Z"])
    _seed_scan_dirs(reports_dir, "gamma", ["20240101T000000Z", "20240102T000000Z"])

    result = runner.invoke(
        app,
        [
            "prune-reports",
            str(project),
            "--keep",
            "1",
            "--project",
            "alpha",
            "--project",
            "gamma",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert "Project: alpha" in result.stdout
    assert "Project: gamma" in result.stdout
    assert "Project: beta" not in result.stdout


def test_prune_reports_project_filter_validates_all_exist(tmp_path: Path) -> None:
    project = tmp_path / "repo5"
    project.mkdir()
    reports_dir = project / "reports"
    (project / ".codegauge.toml").write_text(f'reports_dir = "{reports_dir.as_posix()}"\n')
    _seed_scan_dirs(reports_dir, "alpha", ["20240101T000000Z"])

    result = runner.invoke(
        app,
        [
            "prune-reports",
            str(project),
            "--keep",
            "1",
            "--project",
            "alpha",
            "--project",
            "missing",
        ],
    )
    assert result.exit_code == 3
    assert "Project(s) not found in reports: missing" in result.stderr
