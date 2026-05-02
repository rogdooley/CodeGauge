from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

DEFAULT_SCANNER_NAMES: frozenset[str] = frozenset(
    {
        "ruff",
        "pyright",
        "phpstan",
        "composer_audit",
        "phpcs",
        "opengrep_php",
        "go_vet",
        "staticcheck",
        "govulncheck",
        "go_coverage",
        "opengrep_go",
        "coverage",
        "radon",
        "vulture",
        "bandit",
        "opengrep",
        "opengrep_infra",
        "dockerfile_scan",
        "compose_scan",
        "quadlet_scan",
        "reverse_proxy_scan",
        "terraform_scan",
        "shellcheck",
        "django_check_deploy",
        "django_settings_scan",
        "django_template_scan",
        "django_orm_health",
        "spotbugs",
        "pmd",
        "checkstyle",
        "errorprone",
        "jacoco",
        "dependency_check",
        "opengrep_java",
        "eslint",
        "typescript_diagnostics",
        "npm_audit",
        "js_coverage",
        "opengrep_js",
        "gitleaks",
        "trufflehog",
        "secrets_heuristic",
        "git_history_secrets",
    }
)


def _known_scanners(info: ValidationInfo) -> frozenset[str]:
    if info.context and isinstance(info.context.get("known_scanners"), set):
        return frozenset(info.context["known_scanners"])
    if info.context and isinstance(info.context.get("known_scanners"), frozenset):
        return info.context["known_scanners"]
    return DEFAULT_SCANNER_NAMES


class ScannerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    timeout_seconds: int | None = Field(default=None, ge=1)
    extra_args: list[str] = Field(default_factory=list)


class ThresholdConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_critical: int | None = Field(default=None, ge=0)
    max_high: int | None = Field(default=None, ge=0)
    min_overall_score: float | None = Field(default=None, ge=0, le=100)
    min_security_score: float | None = Field(default=None, ge=0, le=100)
    min_coverage_percent: float | None = Field(default=None, ge=0, le=100)
    max_complexity_grade: str | None = Field(default=None)

    @field_validator("max_complexity_grade")
    @classmethod
    def validate_complexity_grade(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = value.upper()
        if normalized not in {"A", "B", "C", "D", "E", "F"}:
            raise ValueError("max_complexity_grade must be one of A, B, C, D, E, F")
        return normalized


class PayloadConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capture_full_raw: bool = False
    redact: bool = True
    max_bytes_per_finding: int = Field(default=16 * 1024, ge=1024)
    max_bytes_global: int = Field(default=10 * 1024 * 1024, ge=1024)


class SecretsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    history_scan_enabled: bool = False
    history_commit_limit: int = Field(default=5000, ge=1)
    history_size_limit_mb: int = Field(default=1000, ge=1)
    exclude_fixtures: bool = True
    fail_on_secret: bool = False
    ignored_sensitive_patterns_add: list[str] = Field(default_factory=list)
    ignored_sensitive_patterns_remove: list[str] = Field(default_factory=list)


class CodeGaugeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path_fields: ClassVar[tuple[str, ...]] = ("report_root", "state_root")

    report_root: Path
    state_root: Path
    open_report: bool = False
    default_timeout_seconds: int = Field(default=120, ge=1)
    exclude: list[str] = Field(default_factory=list)
    enabled_scanners: list[str] = Field(default_factory=list)
    disabled_scanners: list[str] = Field(default_factory=list)
    scanners: dict[str, ScannerSettings] = Field(default_factory=dict)
    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)
    payload: PayloadConfig = Field(default_factory=PayloadConfig)
    secrets: SecretsConfig = Field(default_factory=SecretsConfig)

    @field_validator("enabled_scanners", "disabled_scanners", mode="after")
    @classmethod
    def validate_scanner_name_lists(
        cls,
        scanner_names: list[str],
        info: ValidationInfo,
    ) -> list[str]:
        allowed = _known_scanners(info)
        unknown = sorted(set(scanner_names) - allowed)
        if unknown:
            raise ValueError(f"Unknown scanner names: {', '.join(unknown)}")
        return scanner_names

    @field_validator("scanners", mode="after")
    @classmethod
    def validate_scanner_settings_keys(
        cls,
        scanner_settings: dict[str, ScannerSettings],
        info: ValidationInfo,
    ) -> dict[str, ScannerSettings]:
        allowed = _known_scanners(info)
        unknown = sorted(set(scanner_settings.keys()) - allowed)
        if unknown:
            raise ValueError(f"Unknown scanner names: {', '.join(unknown)}")
        return scanner_settings

    @model_validator(mode="after")
    def validate_enabled_disabled_overlap(self) -> CodeGaugeConfig:
        overlap = sorted(set(self.enabled_scanners).intersection(self.disabled_scanners))
        if overlap:
            raise ValueError(
                f"Scanners cannot be in both enabled_scanners and disabled_scanners: {', '.join(overlap)}"
            )
        return self

    def resolved_for_project(self, project_root: Path) -> CodeGaugeConfig:
        updated: dict[str, Any] = {}
        for field_name in self.path_fields:
            path_value = getattr(self, field_name)
            expanded = path_value.expanduser()
            if not expanded.is_absolute():
                expanded = (project_root / expanded).resolve()
            else:
                expanded = expanded.resolve()
            updated[field_name] = expanded
        return self.model_copy(update=updated, deep=True)
