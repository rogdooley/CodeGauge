from __future__ import annotations

from pathlib import Path

import pytest

from codegauge.config.config import ConfigLoadError, load_config


def test_config_loads_defaults_for_project(tmp_path: Path) -> None:
    config = load_config(project_path=tmp_path)
    assert config.default_timeout_seconds == 120
    assert config.reports_dir == (tmp_path / ".codegauge/reports").resolve()
    assert config.site_dir == (tmp_path / ".codegauge/site").resolve()
    assert config.payload.capture_full_raw is False
    assert config.payload.redact is True


def test_malformed_toml_fails_with_clear_error(tmp_path: Path) -> None:
    (tmp_path / ".codegauge.toml").write_text("reports_dir = [\n")
    with pytest.raises(ConfigLoadError, match="Invalid TOML"):
        load_config(project_path=tmp_path)


def test_unknown_top_level_key_fails_closed(tmp_path: Path) -> None:
    (tmp_path / ".codegauge.toml").write_text('bad_key = "nope"\n')
    with pytest.raises(ConfigLoadError, match="bad_key"):
        load_config(project_path=tmp_path)


def test_unknown_scanner_name_fails_closed(tmp_path: Path) -> None:
    (tmp_path / ".codegauge.toml").write_text('enabled_scanners = ["not-a-real-scanner"]\n')
    with pytest.raises(ConfigLoadError, match="Unknown scanner names"):
        load_config(project_path=tmp_path)


def test_enabled_disabled_conflict_fails_closed(tmp_path: Path) -> None:
    (tmp_path / ".codegauge.toml").write_text(
        "\n".join(
            [
                'enabled_scanners = ["ruff"]',
                'disabled_scanners = ["ruff"]',
            ]
        )
    )
    with pytest.raises(ConfigLoadError, match="both enabled_scanners and disabled_scanners"):
        load_config(project_path=tmp_path)


def test_project_config_overrides_global_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_home = tmp_path / "home"
    global_cfg = fake_home / ".config" / "codegauge" / "config.toml"
    global_cfg.parent.mkdir(parents=True)
    global_cfg.write_text(
        "\n".join(
            [
                "default_timeout_seconds = 200",
                'exclude = ["global/**"]',
                "",
                "[scanners.ruff]",
                "enabled = true",
                "timeout_seconds = 100",
            ]
        )
    )
    monkeypatch.setenv("HOME", str(fake_home))

    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / ".codegauge.toml").write_text(
        "\n".join(
            [
                "default_timeout_seconds = 50",
                'exclude = ["project/**"]',
                "",
                "[scanners.ruff]",
                "enabled = false",
            ]
        )
    )

    config = load_config(project_path=project_root)
    assert config.default_timeout_seconds == 50
    assert config.exclude == ["project/**"]
    assert config.scanners["ruff"].enabled is False
    assert config.scanners["ruff"].timeout_seconds == 100


def test_paths_expand_user_and_resolve_to_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_home = tmp_path / "home2"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))

    project_root = tmp_path / "project2"
    project_root.mkdir()
    (project_root / ".codegauge.toml").write_text(
        "\n".join(
            [
                'reports_dir = "~/codegauge/reports"',
                'site_dir = "artifacts/site"',
            ]
        )
    )

    config = load_config(project_path=project_root)
    assert config.reports_dir == (fake_home / "codegauge/reports").resolve()
    assert config.site_dir == (project_root / "artifacts/site").resolve()
