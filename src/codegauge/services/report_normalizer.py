from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence
from uuid import UUID

from ..domain.models import Finding

FINGERPRINT_VERSION = "1"
MESSAGE_NORMALIZER_VERSION = "1"

_PARSER_CATEGORY = "system/parser"
_SENSITIVE_KEY_RE = re.compile(
    r"token|secret|authorization|cookie|password|key|jwt|bearer|session|credential",
    re.IGNORECASE,
)
_PEM_RE = re.compile(r"-----BEGIN[\s\S]*?-----END[\s\S]*?-----", re.MULTILINE)
_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
_LINE_RE = re.compile(r"\bline\s+\d+\b", re.IGNORECASE)
_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
_ABS_PATH_RE = re.compile(r"\b(?:/[\w./-]+|[a-zA-Z]:\\[\\\w .-]+)\b")
_REPEAT_PUNCT_RE = re.compile(r"([!?.,:;])\1+")

_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}


def normalize_message(raw: str) -> str:
    msg = raw.strip().lower()
    msg = msg.replace('"', "'")
    msg = msg.replace("\\", "/")
    msg = _LINE_RE.sub("line <n>", msg)
    msg = _HEX_RE.sub("0x<hex>", msg)
    msg = _UUID_RE.sub("<uuid>", msg)
    msg = _ABS_PATH_RE.sub("<path>", msg)
    msg = _REPEAT_PUNCT_RE.sub(r"\1", msg)
    msg = re.sub(r"\s+", " ", msg)
    return msg.strip()


def _safe_uuid(value: str) -> bool:
    try:
        UUID(value)
        return True
    except Exception:
        return False


def _looks_high_entropy(value: str) -> bool:
    if len(value) < 24:
        return False
    unique = len(set(value))
    return unique / len(value) > 0.65


def _redact(obj: Any, *, redact: bool) -> Any:
    if not redact:
        return obj
    if isinstance(obj, dict):
        redacted: dict[str, Any] = {}
        for key, value in obj.items():
            key_s = str(key)
            if _SENSITIVE_KEY_RE.search(key_s):
                redacted[key_s] = "<redacted>"
            else:
                redacted[key_s] = _redact(value, redact=redact)
        return redacted
    if isinstance(obj, list):
        return [_redact(item, redact=redact) for item in obj]
    if isinstance(obj, str):
        value = _PEM_RE.sub("<redacted_pem>", obj)
        if _safe_uuid(value):
            return "<uuid>"
        if _looks_high_entropy(value):
            return "<redacted_entropy>"
        return value
    return obj


def sanitize_raw_payload(
    payload: Mapping[str, Any],
    *,
    redact: bool,
    max_bytes_per_finding: int,
    remaining_global_bytes: int,
) -> tuple[Mapping[str, Any], bool, bool, int]:
    redacted_payload = _redact(dict(payload), redact=redact)
    encoded = json.dumps(redacted_payload, sort_keys=True, ensure_ascii=True).encode("utf-8")
    used = min(len(encoded), max_bytes_per_finding, max(remaining_global_bytes, 0))
    allowed = min(max_bytes_per_finding, max(remaining_global_bytes, 0))
    truncated = len(encoded) > allowed
    if allowed <= 0:
        return {}, True, redact, 0
    if len(encoded) <= allowed:
        return redacted_payload, False, redact, len(encoded)
    cut = encoded[:allowed]
    try:
        compact = json.loads(cut.decode("utf-8", errors="ignore"))
        if isinstance(compact, dict):
            return compact, True, redact, used
    except Exception:
        pass
    return {"truncated": True}, True, redact, used


def _snippet_hash(finding: Finding) -> str | None:
    snippet = finding.raw_payload.get("snippet")
    if isinstance(snippet, str) and snippet.strip():
        return hashlib.sha256(snippet.strip().encode("utf-8")).hexdigest()
    return None


def finding_fingerprint(finding: Finding, *, include_tool: bool = True) -> str:
    normalized_path = finding.file.as_posix()
    normalized_message = normalize_message(finding.message)
    symbol = (finding.symbol or "").strip()
    tool = finding.tool if include_tool else "_"
    if symbol:
        material = f"{tool}|{finding.rule_id}|{normalized_path}|{symbol}"
    else:
        snippet = _snippet_hash(finding)
        if snippet is not None:
            material = f"{tool}|{finding.rule_id}|{normalized_path}|{normalized_message}|{snippet}"
        else:
            material = f"{tool}|{finding.rule_id}|{normalized_path}|{normalized_message}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def infer_ownership(path: Path) -> tuple[str, float]:
    text = path.as_posix().lower()
    if any(part in text for part in ("/vendor/", "/node_modules/", "/third_party/", "/.venv/")):
        return "third_party", 0.98
    if any(part in text for part in ("/dist/", "/build/", "/generated/", "_generated")):
        return "generated", 0.9
    return "first_party", 0.95


def normalize_finding_record(
    finding: Finding,
    *,
    capture_full_raw: bool,
    redact_payload: bool,
    max_bytes_per_finding: int,
    remaining_global_bytes: int,
) -> tuple[dict[str, Any], int]:
    severity = finding.severity.value
    native = finding.raw_payload.get("native_severity") if isinstance(finding.raw_payload, Mapping) else None
    native_severity = str(native) if native is not None else severity
    ownership, confidence = infer_ownership(finding.file)
    sanitized_payload, truncated, redacted, used_bytes = sanitize_raw_payload(
        finding.raw_payload,
        redact=redact_payload and not capture_full_raw,
        max_bytes_per_finding=max_bytes_per_finding,
        remaining_global_bytes=remaining_global_bytes,
    )
    payload = finding.model_dump(mode="json")
    payload.update(
        {
            "tool": finding.tool,
            "rule_id": finding.rule_id,
            "native_severity": native_severity,
            "severity": severity,
            "category": finding.category.value,
            "normalized_message": normalize_message(finding.message),
            "ownership": ownership,
            "ownership_confidence": confidence,
            "fingerprint": finding_fingerprint(finding),
            "raw_payload": sanitized_payload,
            "raw_payload_truncated": truncated,
            "raw_payload_redacted": redacted,
            "fingerprint_version": FINGERPRINT_VERSION,
            "message_normalizer_version": MESSAGE_NORMALIZER_VERSION,
        }
    )
    return payload, used_bytes


def parser_finding(
    *,
    rule_id: str,
    message: str,
    tool: str,
    raw_payload: Mapping[str, Any] | None = None,
) -> Finding:
    from ..domain.models import Category, Language, Severity

    return Finding(
        tool="codegauge",
        rule_id=rule_id,
        severity=Severity.medium,
        category=Category.system_parser,
        language=Language.general,
        file=Path(f"scanners/{tool}"),
        line=None,
        column=None,
        symbol=tool,
        message=message,
        remediation="Inspect scanner parser output and adapter contract.",
        confidence=1.0,
        tags=["system", "parser"],
        raw_payload=dict(raw_payload or {}),
    )


def finding_sort_key(payload: Mapping[str, Any]) -> tuple[Any, ...]:
    severity = str(payload.get("severity", "info"))
    return (
        _SEVERITY_RANK.get(severity, 5),
        str(payload.get("category", "")),
        str(payload.get("file", "")),
        str(payload.get("rule_id", "")),
        str(payload.get("fingerprint", "")),
    )


def parser_category_name() -> str:
    return _PARSER_CATEGORY
