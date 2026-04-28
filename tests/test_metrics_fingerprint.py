from __future__ import annotations

from pathlib import Path

from codegauge.domain.models import Category, Finding, Language, Severity
from codegauge.services.metrics import finding_fingerprint


def _finding(*, tool: str = "ruff", message: str = "Unused   import foo") -> Finding:
    return Finding(
        tool=tool,
        rule_id="F401",
        severity=Severity.low,
        category=Category.dead_code,
        language=Language.python,
        file=Path("src/app.py"),
        line=4,
        message=message,
    )


def test_finding_fingerprint_normalizes_message_spacing_and_case() -> None:
    a = finding_fingerprint(_finding(message="Unused   import Foo"), include_tool=True)
    b = finding_fingerprint(_finding(message="unused import foo"), include_tool=True)
    assert a == b


def test_finding_fingerprint_changes_with_tool_when_requested() -> None:
    ruff_fingerprint = finding_fingerprint(_finding(tool="ruff"), include_tool=True)
    vulture_fingerprint = finding_fingerprint(_finding(tool="vulture"), include_tool=True)
    assert ruff_fingerprint != vulture_fingerprint


def test_finding_fingerprint_ignores_tool_for_cross_tool_dedupe_key() -> None:
    ruff_fingerprint = finding_fingerprint(_finding(tool="ruff"), include_tool=False)
    vulture_fingerprint = finding_fingerprint(_finding(tool="vulture"), include_tool=False)
    assert ruff_fingerprint == vulture_fingerprint

