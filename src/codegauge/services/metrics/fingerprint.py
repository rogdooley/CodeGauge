from __future__ import annotations

from ...domain.models import Finding
from ..report_normalizer import finding_fingerprint as _finding_fingerprint


def finding_fingerprint(finding: Finding, *, include_tool: bool = True) -> str:
    return _finding_fingerprint(finding, include_tool=include_tool)
