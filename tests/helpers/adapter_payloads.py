from __future__ import annotations

import json


def make_tsc_json_diagnostics_payload(*, file: str, code: str, message: str, line: int, column: int) -> str:
    payload = {
        "diagnostics": [
            {
                "file": file,
                "code": code,
                "message": message,
                "line": line,
                "column": column,
            }
        ]
    }
    return json.dumps(payload)


def make_npm_audit_envelope(*, tool: str, payload: dict) -> str:
    return json.dumps({"tool": tool, "stdout": json.dumps(payload)})


def make_django_check_payload(*, stdout: str, stderr: str = "") -> str:
    return json.dumps({"stdout": stdout, "stderr": stderr})
