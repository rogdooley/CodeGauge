from __future__ import annotations

import hashlib
import re

from ...domain.models import Finding


def normalize_finding_message(message: str) -> str:
    return re.sub(r"\s+", " ", message).strip().lower()


def finding_fingerprint(finding: Finding, *, include_tool: bool = True) -> str:
    message_hash = hashlib.sha1(normalize_finding_message(finding.message).encode("utf-8")).hexdigest()
    base = f"{finding.category.value}|{finding.rule_id}|{finding.file.as_posix()}|{finding.line}|{message_hash}"
    if include_tool:
        return f"{finding.tool}|{base}"
    return base

