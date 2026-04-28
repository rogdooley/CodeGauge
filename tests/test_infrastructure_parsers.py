from __future__ import annotations

import json
from pathlib import Path

from codegauge.domain.models import Category, Severity
from codegauge.parsers import (
    ComposeScanParser,
    DockerfileScanParser,
    OpenGrepInfraParser,
    QuadletScanParser,
    ReverseProxyScanParser,
    ShellCheckParser,
    TerraformScanParser,
)


def test_dockerfile_scan_parser_parses_findings_and_metadata() -> None:
    stdout = json.dumps(
        {
            "findings": [
                {
                    "rule_id": "INF.CONTAINER.USER_ROOT",
                    "file": "Dockerfile",
                    "line": 1,
                    "message": "Container runs as root",
                    "severity": "high",
                }
            ],
            "scalar_metrics": {"dockerfile_count": 2},
        }
    )
    parser = DockerfileScanParser()
    findings = parser.parse(stdout, "", Path.cwd())
    metadata = parser.parse_metadata(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].severity == Severity.high
    assert metadata["scalar_metrics"]["dockerfile_count"] == 2


def test_compose_scan_parser_parses_findings() -> None:
    stdout = json.dumps(
        {
            "findings": [
                {
                    "rule_id": "INF.COMPOSE.PRIVILEGED",
                    "file": "compose.yml",
                    "line": 3,
                    "message": "Privileged container enabled",
                    "severity": "high",
                }
            ]
        }
    )
    findings = ComposeScanParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].category == Category.security


def test_quadlet_scan_parser_parses_findings() -> None:
    stdout = json.dumps(
        {
            "findings": [
                {
                    "rule_id": "INF.QUADLET.ROOT_USER",
                    "file": "app.container",
                    "line": 1,
                    "message": "Root user",
                    "severity": "high",
                }
            ]
        }
    )
    findings = QuadletScanParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].severity == Severity.high


def test_reverse_proxy_scan_parser_parses_findings() -> None:
    stdout = json.dumps(
        {
            "findings": [
                {
                    "rule_id": "INF.PROXY.LEGACY_TLS",
                    "file": "nginx.conf",
                    "line": 2,
                    "message": "Legacy TLS",
                    "severity": "high",
                }
            ]
        }
    )
    findings = ReverseProxyScanParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].category == Category.security


def test_terraform_scan_parser_parses_findings() -> None:
    stdout = json.dumps(
        {
            "findings": [
                {
                    "rule_id": "INF.TF.OPEN_WORLD",
                    "file": "main.tf",
                    "line": 8,
                    "message": "Open world CIDR",
                    "severity": "high",
                }
            ],
            "scalar_metrics": {"terraform_file_count": 1},
        }
    )
    parser = TerraformScanParser()
    findings = parser.parse(stdout, "", Path.cwd())
    metadata = parser.parse_metadata(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert metadata["scalar_metrics"]["terraform_file_count"] == 1


def test_shellcheck_parser_parses_json_findings() -> None:
    stdout = json.dumps(
        [
            {
                "file": "scripts/deploy.sh",
                "line": 3,
                "code": 2086,
                "level": "warning",
                "message": "Double quote to prevent globbing",
            }
        ]
    )
    findings = ShellCheckParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].rule_id == "SHELLCHECK.SC2086"


def test_opengrep_infra_parser_parses_sarif_findings() -> None:
    stdout = json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "INF.SEC.SECRETS",
                            "message": {"text": "Secret exposed"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "docker-compose.yml"},
                                        "region": {"startLine": 12, "startColumn": 1},
                                    }
                                }
                            ],
                        }
                    ]
                }
            ],
        }
    )
    findings = OpenGrepInfraParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].category == Category.security
