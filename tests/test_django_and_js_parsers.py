from __future__ import annotations

import json
from pathlib import Path

import pytest

from codegauge.domain.models import Category, Severity
from codegauge.parsers import (
    DjangoCheckDeployParser,
    DjangoOrmHealthParser,
    DjangoSettingsScanParser,
    DjangoTemplateScanParser,
    ESLintParser,
    JSCoverageParser,
    NPMAuditParser,
    OpenGrepJSParser,
    TypeScriptDiagnosticsParser,
)
from codegauge.parsers.base import ScannerOutputInvalidError


def test_django_check_deploy_parser_parses_warnings() -> None:
    stdout = '{"returncode":1,"stdout":"?: (security.W001) You do not have \'SecurityMiddleware\'\\n","stderr":""}'
    findings = DjangoCheckDeployParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].category == Category.security
    assert findings[0].severity == Severity.high


def test_django_settings_parser_parses_findings() -> None:
    stdout = (
        '{"findings":[{"rule_id":"DJG.SET.DEBUG_TRUE","file":"app/settings.py","line":10,'
        '"message":"DEBUG should be False in production","severity":"high"}]}'
    )
    findings = DjangoSettingsScanParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].rule_id == "DJG.SET.DEBUG_TRUE"
    assert findings[0].severity == Severity.high


def test_django_template_parser_parses_findings() -> None:
    stdout = (
        '{"findings":[{"rule_id":"DJG.TPL.AUTOESCAPE_OFF","file":"templates/a.html","line":3,'
        '"message":"Template disables autoescape","severity":"high"}]}'
    )
    findings = DjangoTemplateScanParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].category == Category.security


def test_django_orm_parser_parses_findings() -> None:
    stdout = (
        '{"findings":[{"rule_id":"DJG.ORM.RAW_SQL_USAGE","file":"app/models.py","line":12,'
        '"message":"Raw SQL usage detected","severity":"medium"}]}'
    )
    findings = DjangoOrmHealthParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].category == Category.maintainability


def test_eslint_parser_parses_findings() -> None:
    stdout = (
        '[{"filePath":"src/app.ts","messages":[{"ruleId":"TS.NO-UNUSED","message":"unused var",'
        '"line":2,"column":5,"severity":2}]}]'
    )
    findings = ESLintParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].category == Category.typing


def test_typescript_diagnostics_parser_parses_stderr_lines() -> None:
    stderr = "src/app.ts(5,10): error TS2322: Type 'number' is not assignable to type 'string'."
    findings = TypeScriptDiagnosticsParser().parse("", stderr, Path.cwd())
    assert len(findings) == 1
    assert findings[0].category == Category.typing
    assert findings[0].severity == Severity.high


def test_typescript_diagnostics_parser_parses_json_contract() -> None:
    stdout = (
        '{"diagnostics":[{"file":"src/app.ts","code":"TS2345",'
        '"message":"Argument of type number is not assignable","line":9,"column":3}]}'
    )
    findings = TypeScriptDiagnosticsParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].rule_id == "TS2345"


def test_npm_audit_parser_parses_vulnerabilities() -> None:
    stdout = json.dumps(
        {
            "tool": "npm",
            "stdout": json.dumps(
                {
                    "vulnerabilities": {
                        "lodash": {
                            "severity": "high",
                            "via": [{"source": "GHSA-xxxx"}],
                            "title": "Prototype pollution",
                        }
                    }
                }
            ),
        }
    )
    findings = NPMAuditParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].category == Category.security


def test_npm_audit_parser_parses_v1_advisories_contract() -> None:
    stdout = json.dumps(
        {
            "tool": "npm",
            "stdout": json.dumps(
                {
                    "advisories": {
                        "1179": {
                            "module_name": "lodash",
                            "title": "Prototype Pollution",
                            "severity": "high",
                            "cves": ["CVE-2019-10744"],
                        }
                    }
                }
            ),
        }
    )
    findings = NPMAuditParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].category == Category.security


def test_npm_audit_parser_parses_yarn_event_contract() -> None:
    stdout = json.dumps(
        {
            "tool": "yarn",
            "stdout": json.dumps(
                {
                    "type": "auditAdvisory",
                    "data": {
                        "advisory": {
                            "id": 1200,
                            "module_name": "minimist",
                            "severity": "moderate",
                            "title": "Prototype Pollution",
                        }
                    },
                }
            ),
        }
    )
    findings = NPMAuditParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].category == Category.security


def test_npm_audit_parser_fails_closed_for_unknown_tool_with_invalid_schema() -> None:
    stdout = json.dumps({"tool": "unknown", "stdout": json.dumps({"something": "else"})})
    with pytest.raises(ScannerOutputInvalidError):
        NPMAuditParser().parse(stdout, "", Path.cwd())


def test_js_coverage_parser_extracts_scalar_metrics() -> None:
    stdout = '{"total":{"lines":{"pct":87.5},"branches":{"pct":72.0}}}'
    metadata = JSCoverageParser().parse_metadata(stdout, "", Path.cwd())
    assert metadata["scalar_metrics"]["coverage_percent"] == 87.5
    assert metadata["scalar_metrics"]["branch_coverage_percent"] == 72.0


def test_opengrep_js_parser_maps_categories() -> None:
    stdout = (
        '{"version":"2.1.0","runs":[{"results":[{"ruleId":"SEC.XSS","message":{"text":"xss"},'
        '"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/app.js"},"region":{"startLine":4,"startColumn":1}}}]}]}]}'
    )
    findings = OpenGrepJSParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].category == Category.security
    assert findings[0].severity == Severity.high
