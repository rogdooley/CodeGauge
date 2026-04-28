from __future__ import annotations

from pathlib import Path

import pytest

from codegauge.domain.models import Category, Severity
from codegauge.parsers.base import ScannerOutputInvalidError
from codegauge.parsers.opengrep_parser import OpenGrepParser, load_opengrep_rule_mapping


def test_opengrep_parser_parses_sarif_findings() -> None:
    parser = OpenGrepParser()
    stdout = (
        '{"version":"2.1.0","runs":[{"results":['
        '{"ruleId":"SEC.SQLI","message":{"text":"Potential SQL injection"},'
        '"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/app.py"},"region":{"startLine":12,"startColumn":4}}}]},'
        '{"ruleId":"DEAD.UNUSED","message":{"text":"Unused code"},'
        '"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/app.py"},"region":{"startLine":20,"startColumn":1}}}]}'
        ']}]}'
    )
    findings = parser.parse(stdout, "", Path.cwd())
    assert len(findings) == 2
    assert findings[0].severity == Severity.high
    assert findings[0].category == Category.security
    assert findings[1].category == Category.dead_code


def test_opengrep_mapping_prefers_longest_prefix(tmp_path: Path) -> None:
    mapping_file = tmp_path / "opengrep_rules.toml"
    mapping_file.write_text(
        "\n".join(
            [
                "[defaults]",
                'severity = "medium"',
                'category = "lint"',
                "",
                "[severity_prefixes]",
                'SEC = "high"',
                '"SEC.SQLI" = "critical"',
                "",
                "[category_prefixes]",
                'SEC = "security"',
                '"SEC.SQLI" = "security"',
            ]
        )
    )
    parser = OpenGrepParser(load_opengrep_rule_mapping(mapping_file))
    findings = parser.parse(
        '{"version":"2.1.0","runs":[{"results":[{"ruleId":"SEC.SQLI.1","message":{"text":"x"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":1,"startColumn":1}}}]}]}]}',
        "",
        Path.cwd(),
    )
    assert findings[0].severity == Severity.critical


def test_opengrep_parser_rejects_missing_location() -> None:
    parser = OpenGrepParser()
    with pytest.raises(ScannerOutputInvalidError):
        parser.parse(
            '{"version":"2.1.0","runs":[{"results":[{"ruleId":"SEC","message":{"text":"x"},"locations":[]}]}]}',
            "",
            Path.cwd(),
        )
