from __future__ import annotations

from pathlib import Path

from codegauge.domain.models import Category, Finding, Language, Severity
from codegauge.services.report_normalizer import (
    finding_fingerprint,
    finding_sort_key,
    normalize_finding_record,
    normalize_message,
)


def _finding(*, line: int = 10, message: str = "Unused import OrderedDict") -> Finding:
    return Finding(
        tool="ruff",
        rule_id="F401",
        severity=Severity.low,
        category=Category.dead_code,
        language=Language.python,
        file=Path("app/web/routes/discover.py"),
        line=line,
        message=message,
        symbol="OrderedDict",
        raw_payload={"native_severity": "error", "token": "abc123"},
    )


def test_fingerprint_ignores_line_numbers() -> None:
    assert finding_fingerprint(_finding(line=1)) == finding_fingerprint(_finding(line=200))


def test_normalize_message_is_conservative() -> None:
    left = normalize_message("Unused   import OrderedDict at line 123")
    right = normalize_message("unused import OrderedDict at line 998")
    assert left == right
    assert "ordereddict" in left


def test_normalized_record_has_required_fields() -> None:
    payload, _ = normalize_finding_record(
        _finding(),
        capture_full_raw=False,
        redact_payload=True,
        max_bytes_per_finding=16 * 1024,
        remaining_global_bytes=16 * 1024,
    )
    for key in (
        "tool",
        "rule_id",
        "native_severity",
        "severity",
        "ownership",
        "ownership_confidence",
        "fingerprint",
    ):
        assert key in payload
    assert payload["raw_payload_redacted"] is True


def test_finding_sort_key_is_deterministic() -> None:
    a = {"severity": "high", "category": "security", "file": "a.py", "rule_id": "X", "fingerprint": "1"}
    b = {"severity": "low", "category": "lint", "file": "b.py", "rule_id": "Y", "fingerprint": "2"}
    first = sorted([b, a], key=finding_sort_key)
    second = sorted([b, a], key=finding_sort_key)
    assert first == second
    assert first[0]["severity"] == "high"
