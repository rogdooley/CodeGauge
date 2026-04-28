from __future__ import annotations

import json

from typer.testing import CliRunner

from codegauge.cli import app


runner = CliRunner()


def test_list_scanners_json_shape() -> None:
    result = runner.invoke(app, ["list-scanners", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert isinstance(payload, list)
    assert payload
    required = {"scanner_name", "available", "parser_registered", "expected_parser", "status"}
    for entry in payload:
        assert required.issubset(entry.keys())
        assert entry["status"] in {"ready", "incomplete", "unavailable"}
        assert isinstance(entry["expected_parser"], str)
        assert entry["expected_parser"]
        if entry["available"] is False:
            assert entry["status"] == "unavailable"
        if entry["available"] is True and entry["parser_registered"] is True:
            assert entry["status"] == "ready"
    by_name = {entry["scanner_name"]: entry for entry in payload}
    assert by_name["ruff"]["expected_parser"] == "ruff_parser"
    assert by_name["pyright"]["expected_parser"] == "pyright_parser"
    assert by_name["coverage"]["expected_parser"] == "coverage_parser"
    assert by_name["radon"]["expected_parser"] == "radon_parser"
    assert by_name["vulture"]["expected_parser"] == "vulture_parser"
    assert by_name["opengrep"]["expected_parser"] == "opengrep_parser"
    assert by_name["opengrep_infra"]["expected_parser"] == "opengrep_infra_parser"
    assert by_name["dockerfile_scan"]["expected_parser"] == "dockerfile_scan_parser"
    assert by_name["compose_scan"]["expected_parser"] == "compose_scan_parser"
    assert by_name["quadlet_scan"]["expected_parser"] == "quadlet_scan_parser"
    assert by_name["reverse_proxy_scan"]["expected_parser"] == "reverse_proxy_scan_parser"
    assert by_name["terraform_scan"]["expected_parser"] == "terraform_scan_parser"
    assert by_name["shellcheck"]["expected_parser"] == "shellcheck_parser"
    assert by_name["spotbugs"]["expected_parser"] == "spotbugs_parser"
    assert by_name["pmd"]["expected_parser"] == "pmd_parser"
    assert by_name["checkstyle"]["expected_parser"] == "checkstyle_parser"
    assert by_name["errorprone"]["expected_parser"] == "errorprone_parser"
    assert by_name["jacoco"]["expected_parser"] == "jacoco_parser"
    assert by_name["dependency_check"]["expected_parser"] == "dependency_check_parser"
    assert by_name["opengrep_java"]["expected_parser"] == "opengrep_java_parser"
    assert by_name["django_check_deploy"]["expected_parser"] == "django_check_deploy_parser"
    assert by_name["django_settings_scan"]["expected_parser"] == "django_settings_scan_parser"
    assert by_name["django_template_scan"]["expected_parser"] == "django_template_scan_parser"
    assert by_name["django_orm_health"]["expected_parser"] == "django_orm_health_parser"
    assert by_name["eslint"]["expected_parser"] == "eslint_parser"
    assert by_name["typescript_diagnostics"]["expected_parser"] == "typescript_diagnostics_parser"
    assert by_name["npm_audit"]["expected_parser"] == "npm_audit_parser"
    assert by_name["js_coverage"]["expected_parser"] == "js_coverage_parser"
    assert by_name["opengrep_js"]["expected_parser"] == "opengrep_js_parser"


def test_list_scanners_human_output() -> None:
    result = runner.invoke(app, ["list-scanners"])
    assert result.exit_code == 0
    assert "Available scanners:" in result.stdout
    assert "status=" in result.stdout
