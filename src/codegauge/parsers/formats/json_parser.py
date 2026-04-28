from __future__ import annotations

import json
from typing import Any

from ..base import ScannerOutputInvalidError


def parse_json_document(stdout: str, *, scanner_name: str) -> Any:
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ScannerOutputInvalidError(f"invalid {scanner_name} JSON output: {exc}") from exc


def require_object(value: Any, *, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ScannerOutputInvalidError(f"{context} must be an object")
    return value


def require_list(value: Any, *, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ScannerOutputInvalidError(f"{context} must be a list")
    return value


def require_string(value: Any, *, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ScannerOutputInvalidError(f"{context} must be a non-empty string")
    return value
