from __future__ import annotations

from typing import Any

from ..base import ScannerOutputInvalidError
from .json_parser import parse_json_document, require_list, require_object


def parse_sarif_runs(stdout: str, *, scanner_name: str) -> list[dict[str, Any]]:
    payload = parse_json_document(stdout, scanner_name=scanner_name)
    root = require_object(payload, context=f"{scanner_name} SARIF root")
    runs = require_list(root.get("runs"), context=f"{scanner_name} SARIF runs")
    normalized: list[dict[str, Any]] = []
    for idx, run in enumerate(runs):
        try:
            normalized.append(require_object(run, context=f"{scanner_name} SARIF run[{idx}]"))
        except ScannerOutputInvalidError as exc:
            raise ScannerOutputInvalidError(str(exc)) from exc
    return normalized
