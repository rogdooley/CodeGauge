from __future__ import annotations

import copy
import tomllib
from pathlib import Path
from typing import Any, Mapping

from pydantic import ValidationError

from ..paths import default_report_root, default_state_root
from .schema import CodeGaugeConfig, DEFAULT_SCANNER_NAMES


class ConfigLoadError(ValueError):
    """Raised when config loading or validation fails."""


def _default_config() -> dict[str, Any]:
    return {
        "report_root": str(default_report_root()),
        "state_root": str(default_state_root()),
        "open_report": False,
        "default_timeout_seconds": 120,
        "exclude": [],
        "enabled_scanners": [],
        "disabled_scanners": [],
        "scanners": {},
        "thresholds": {},
        "payload": {},
    }


def _deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        current = merged.get(key)
        if isinstance(current, Mapping) and isinstance(value, Mapping):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


def _read_toml(path: Path) -> Mapping[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigLoadError(f"Invalid TOML in {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ConfigLoadError(f"Invalid config structure in {path}: expected a TOML table")
    return payload


def _project_root(project_path: Path | None) -> Path:
    if project_path is None:
        return Path.cwd().resolve()
    return project_path.expanduser().resolve()


def load_config(
    project_path: Path | None = None,
    overrides: Mapping[str, Any] | None = None,
    known_scanners: set[str] | None = None,
) -> CodeGaugeConfig:
    """
    Load and merge config in this order:
    1) built-in defaults
    2) ~/.config/codegauge/config.toml
    3) <project>/.codegauge.toml
    4) explicit CLI overrides
    """
    project_root = _project_root(project_path)
    global_config_path = Path("~/.config/codegauge/config.toml").expanduser()
    project_config_path = project_root / ".codegauge.toml"

    merged: dict[str, Any] = copy.deepcopy(_default_config())
    explicit_report_root = False
    explicit_state_root = False
    for source in (
        _read_toml(global_config_path),
        _read_toml(project_config_path),
        dict(overrides or {}),
    ):
        if "report_root" in source:
            explicit_report_root = True
        if "state_root" in source:
            explicit_state_root = True
        merged = _deep_merge(merged, source)

    if not explicit_report_root and isinstance(merged.get("reports_dir"), (str, Path)):
        merged["report_root"] = str(merged["reports_dir"])
    if not explicit_state_root and isinstance(merged.get("site_dir"), (str, Path)):
        merged["state_root"] = str(default_state_root())
    merged.pop("reports_dir", None)
    merged.pop("site_dir", None)

    scanner_names = known_scanners if known_scanners is not None else set(DEFAULT_SCANNER_NAMES)
    try:
        parsed = CodeGaugeConfig.model_validate(merged, context={"known_scanners": scanner_names})
    except ValidationError as exc:
        raise ConfigLoadError(f"Invalid configuration: {exc}") from exc
    return parsed.resolved_for_project(project_root)
