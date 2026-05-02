from __future__ import annotations

from enum import Enum
from typing import Sequence

from pydantic import BaseModel, Field


class PolicyStatus(str, Enum):
    pass_ = "pass"
    warn = "warn"
    fail = "fail"


class PolicyReason(str, Enum):
    scanner_failure = "scanner_failure"
    parser_missing = "parser_missing"
    invalid_findings = "invalid_findings"
    invalid_paths = "invalid_paths"
    baseline_entry_expiring = "baseline_entry_expiring"
    baseline_entry_expired = "baseline_entry_expired"
    baseline_entry_missing_owner = "baseline_entry_missing_owner"
    critical_security_finding = "critical_security_finding"
    high_security_findings = "high_security_findings"
    low_score = "low_score"
    real_secret_exposure = "real_secret_exposure"
    probable_secret_exposure = "probable_secret_exposure"
    private_key_material = "private_key_material"
    baseline_real_secret_prohibited = "baseline_real_secret_prohibited"
    history_scan_skipped = "history_scan_skipped"
    history_scan_stale = "history_scan_stale"
    secret_scanner_unavailable = "secret_scanner_unavailable"


class QualityPolicyResult(BaseModel):
    status: PolicyStatus
    reasons: Sequence[PolicyReason] = Field(default_factory=list)
    violations: Sequence[str] = Field(default_factory=list)
    warnings: Sequence[str] = Field(default_factory=list)
    summary: str
