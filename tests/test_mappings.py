from __future__ import annotations

from pathlib import Path

from codegauge.domain.models import Category, Severity
from codegauge.parsers.opengrep_parser import load_opengrep_rule_mapping
from codegauge.parsers.ruff_parser import RuffParser, load_ruff_rule_mapping


def test_ruff_mapping_loader_reads_defaults_and_prefixes() -> None:
    mapping = load_ruff_rule_mapping()
    assert mapping.default_severity == Severity.medium
    assert mapping.default_category == Category.lint
    assert mapping.severity_prefixes["S"] == Severity.high
    assert mapping.category_prefixes["F401"] == Category.dead_code


def test_ruff_mapping_prefers_longer_prefix(tmp_path: Path) -> None:
    custom = tmp_path / "ruff_rules.toml"
    custom.write_text(
        "\n".join(
            [
                "[defaults]",
                'severity = "medium"',
                'category = "lint"',
                "",
                "[severity_prefixes]",
                'F = "low"',
                'F82 = "high"',
                "",
                "[category_prefixes]",
                'F = "lint"',
                'F82 = "maintainability"',
            ]
        )
    )
    parser = RuffParser(load_ruff_rule_mapping(custom))
    findings = parser.parse(
        '[{"code":"F821","message":"undefined name","filename":"a.py","location":{"row":1,"column":1}}]',
        "",
        Path.cwd(),
    )
    assert findings[0].severity == Severity.high
    assert findings[0].category == Category.maintainability


def test_opengrep_mapping_loader_reads_defaults_and_prefixes() -> None:
    mapping = load_opengrep_rule_mapping()
    assert mapping.default_severity == Severity.medium
    assert mapping.default_category == Category.lint
    assert mapping.severity_prefixes["SEC"] == Severity.high
    assert mapping.category_prefixes["SEC"] == Category.security
