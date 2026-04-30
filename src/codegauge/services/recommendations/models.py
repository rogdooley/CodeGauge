from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class FindingCluster:
    key: tuple[str, str, str, str]
    findings: tuple[Mapping[str, Any], ...]
