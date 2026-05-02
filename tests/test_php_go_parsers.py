from __future__ import annotations

import json
from pathlib import Path

from codegauge.parsers.composer_audit_parser import ComposerAuditParser
from codegauge.parsers.go_coverage_parser import GoCoverageParser
from codegauge.parsers.go_vet_parser import GoVetParser
from codegauge.parsers.govulncheck_parser import GovulncheckParser
from codegauge.parsers.phpstan_parser import PHPStanParser
from codegauge.parsers.phpcs_parser import PHPCSParser
from codegauge.parsers.staticcheck_parser import StaticcheckParser


def test_phpstan_parser_extracts_findings() -> None:
    parser = PHPStanParser()
    stdout = json.dumps(
        {
            "files": {
                "src/Example.php": {
                    "messages": [
                        {
                            "message": "Call to undefined method Foo::bar().",
                            "line": 12,
                            "identifier": "method.notFound",
                        }
                    ]
                }
            }
        }
    )
    findings = parser.parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].rule_id == "METHOD.NOTFOUND"


def test_composer_audit_parser_extracts_advisories() -> None:
    parser = ComposerAuditParser()
    stdout = json.dumps(
        {
            "advisories": [
                {
                    "packageName": "symfony/http-foundation",
                    "cve": "CVE-2025-0001",
                    "title": "Vulnerability",
                    "severity": "high",
                }
            ]
        }
    )
    findings = parser.parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].rule_id == "COMPOSER.AUDIT.CVE-2025-0001"


def test_phpcs_parser_extracts_lint_findings() -> None:
    parser = PHPCSParser()
    stdout = json.dumps(
        {
            "files": {
                "src/Example.php": {
                    "messages": [
                        {
                            "message": "Expected 1 newline at end of file",
                            "line": 10,
                            "column": 1,
                            "source": "PSR12.Files.FileHeader.SpacingAfterBlock",
                            "type": "WARNING",
                        }
                    ]
                }
            }
        }
    )
    findings = parser.parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].tool == "phpcs"


def test_go_vet_parser_extracts_findings() -> None:
    parser = GoVetParser()
    stdout = "cmd/app/main.go:14:2: unreachable code"
    findings = parser.parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].tool == "go_vet"


def test_staticcheck_parser_extracts_findings() -> None:
    parser = StaticcheckParser()
    stdout = json.dumps(
        {
            "code": "SA4006",
            "message": "this value of err is never used",
            "location": {"file": "main.go", "line": 9, "column": 2},
        }
    )
    findings = parser.parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].rule_id == "STATICCHECK.SA4006"


def test_govulncheck_parser_extracts_findings() -> None:
    parser = GovulncheckParser()
    stdout = json.dumps({"vuln": {"osv": "GO-2025-0001", "summary": "Issue"}})
    findings = parser.parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].rule_id == "GOVULNCHECK.GO-2025-0001"


def test_go_coverage_parser_extracts_scalar_metadata() -> None:
    parser = GoCoverageParser()
    stdout = json.dumps({"totals": {"percent_covered": 73.5}})
    metadata = parser.parse_metadata(stdout, "", Path.cwd())
    assert metadata["scalar_metrics"]["coverage_percent"] == 73.5
