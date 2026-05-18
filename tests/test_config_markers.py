from __future__ import annotations

from pathlib import Path

from codegauge.discovery import has_recognized_config_marker


def test_has_recognized_config_marker_detects_exact_marker(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    assert has_recognized_config_marker(project) is True


def test_has_recognized_config_marker_detects_glob_marker(tmp_path: Path) -> None:
    project = tmp_path / "proj_eslint"
    project.mkdir()
    (project / ".eslintrc.json").write_text("{}\n")
    assert has_recognized_config_marker(project) is True


def test_has_recognized_config_marker_returns_false_when_unmanaged(tmp_path: Path) -> None:
    project = tmp_path / "proj_unmanaged"
    project.mkdir()
    (project / "README.md").write_text("hello\n")
    assert has_recognized_config_marker(project) is False
