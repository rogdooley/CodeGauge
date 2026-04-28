from __future__ import annotations

import pytest

from codegauge.parsers.base import ScannerOutputInvalidError
from codegauge.parsers.formats.json_parser import parse_json_document, require_list, require_object, require_string
from codegauge.parsers.formats.sarif_parser import parse_sarif_runs


def test_json_format_helpers_validate_shape() -> None:
    payload = parse_json_document('{"a":[{"b":"c"}]}', scanner_name="test")
    root = require_object(payload, context="root")
    entries = require_list(root["a"], context="entries")
    entry = require_object(entries[0], context="entry")
    assert require_string(entry["b"], context="entry.b") == "c"


def test_sarif_format_parser_returns_runs() -> None:
    runs = parse_sarif_runs('{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}}}]}', scanner_name="sarif")
    assert len(runs) == 1


def test_sarif_format_parser_rejects_invalid_shape() -> None:
    with pytest.raises(ScannerOutputInvalidError):
        parse_sarif_runs('{"version":"2.1.0","runs":"not-a-list"}', scanner_name="sarif")
