from __future__ import annotations

from pathlib import Path

from codegauge.bootstrap.factory import (
    build_scan_services,
    load_resolved_config,
    register_builtin_parsers,
    register_builtin_scanners,
)
from codegauge.services.parser_registry import ParserRegistry
from codegauge.services.scanner_registry import ScannerRegistry


def test_builtin_registration_hooks_register_expected_components() -> None:
    scanner_registry = ScannerRegistry([])
    parser_registry = ParserRegistry()
    register_builtin_scanners(scanner_registry)
    register_builtin_parsers(parser_registry)
    scanner_names = {scanner.scanner_name for scanner in scanner_registry.scanners}
    assert {
        "ruff",
        "pyright",
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
    }.issubset(scanner_names)
    assert parser_registry.get("ruff") is not None
    assert parser_registry.get("pyright") is not None
    assert parser_registry.get("coverage") is not None
    assert parser_registry.get("radon") is not None
    assert parser_registry.get("vulture") is not None
    assert parser_registry.get("bandit") is not None
    assert parser_registry.get("opengrep") is not None
    assert parser_registry.get("opengrep_infra") is not None
    assert parser_registry.get("dockerfile_scan") is not None
    assert parser_registry.get("compose_scan") is not None
    assert parser_registry.get("quadlet_scan") is not None
    assert parser_registry.get("reverse_proxy_scan") is not None
    assert parser_registry.get("terraform_scan") is not None
    assert parser_registry.get("shellcheck") is not None
    assert parser_registry.get("django_check_deploy") is not None
    assert parser_registry.get("django_settings_scan") is not None
    assert parser_registry.get("django_template_scan") is not None
    assert parser_registry.get("django_orm_health") is not None
    assert parser_registry.get("spotbugs") is not None
    assert parser_registry.get("pmd") is not None
    assert parser_registry.get("checkstyle") is not None
    assert parser_registry.get("errorprone") is not None
    assert parser_registry.get("jacoco") is not None
    assert parser_registry.get("dependency_check") is not None
    assert parser_registry.get("opengrep_java") is not None
    assert parser_registry.get("eslint") is not None
    assert parser_registry.get("typescript_diagnostics") is not None
    assert parser_registry.get("npm_audit") is not None
    assert parser_registry.get("js_coverage") is not None
    assert parser_registry.get("opengrep_js") is not None


def test_build_scan_services_composes_registries_and_orchestrator(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')
    services = build_scan_services(project)
    assert services.project_path == project.resolve()
    assert services.project.path == project.resolve()
    assert services.orchestrator is not None
    assert services.parser_registry.get("ruff") is not None
    assert services.parser_registry.get("pyright") is not None
    assert services.parser_registry.get("coverage") is not None
    assert services.parser_registry.get("radon") is not None
    assert services.parser_registry.get("vulture") is not None
    assert services.parser_registry.get("bandit") is not None
    assert services.parser_registry.get("opengrep") is not None
    assert all(scanner.scanner_name == "ruff" for scanner in services.scanner_registry.enabled_scanners(["python"]))


def test_load_resolved_config_uses_builtin_scanner_names(tmp_path: Path) -> None:
    project = tmp_path / "repo2"
    project.mkdir()
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')
    config = load_resolved_config(project)
    assert config.enabled_scanners == ["ruff"]
