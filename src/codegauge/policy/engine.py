from __future__ import annotations

from typing import Sequence

from ..scoring.models import NormalizedMetric, ScoreCard, ScoreCategory
from .models import PolicyReason, PolicyStatus, QualityPolicyResult


class CodeGaugePolicyEngine:
    """Deterministic built-in CodeGauge v1 quality policy evaluation."""

    HIGH_SECURITY_FINDINGS_WARN_THRESHOLD = 3
    WARN_SCORE_THRESHOLD = 80
    FAIL_SCORE_THRESHOLD = 60

    _REASON_ORDER: tuple[PolicyReason, ...] = (
        PolicyReason.scanner_failure,
        PolicyReason.parser_missing,
        PolicyReason.invalid_findings,
        PolicyReason.invalid_paths,
        PolicyReason.baseline_entry_expired,
        PolicyReason.baseline_entry_missing_owner,
        PolicyReason.baseline_entry_expiring,
        PolicyReason.critical_security_finding,
        PolicyReason.high_security_findings,
        PolicyReason.low_score,
        PolicyReason.real_secret_exposure,
        PolicyReason.probable_secret_exposure,
        PolicyReason.private_key_material,
        PolicyReason.baseline_real_secret_prohibited,
        PolicyReason.history_scan_skipped,
        PolicyReason.history_scan_stale,
        PolicyReason.secret_scanner_unavailable,
    )

    def evaluate(
        self,
        *,
        score_card: ScoreCard,
        metrics: Sequence[NormalizedMetric],
        scanner_failures: int,
        parser_missing: int,
        invalid_findings: int,
        invalid_paths: int,
        baseline_expired_entries: int = 0,
        baseline_missing_owner_entries: int = 0,
        baseline_expiring_soon_entries: int = 0,
        real_secret_findings: int = 0,
        probable_secret_findings: int = 0,
        private_key_findings: int = 0,
        baseline_real_secret_entries: int = 0,
        history_scan_skipped: bool = False,
        history_scan_stale: bool = False,
        history_scan_age_days: int | None = None,
        secret_scanner_unavailable_count: int = 0,
    ) -> QualityPolicyResult:
        reason_set: set[PolicyReason] = set()
        violations: list[str] = []
        warnings: list[str] = []

        critical_security_findings = sum(
            metric.count
            for metric in metrics
            if metric.category == ScoreCategory.security and metric.severity.value == "critical"
        )
        high_security_findings = sum(
            metric.count
            for metric in metrics
            if metric.category == ScoreCategory.security and metric.severity.value == "high"
        )

        if critical_security_findings > 0:
            reason_set.add(PolicyReason.critical_security_finding)
            violations.append("critical security findings present")
        if scanner_failures > 0:
            reason_set.add(PolicyReason.scanner_failure)
            violations.append("scanner failures present")
        if parser_missing > 0:
            reason_set.add(PolicyReason.parser_missing)
            violations.append("parser registrations missing")
        if invalid_findings > 0:
            reason_set.add(PolicyReason.invalid_findings)
            violations.append("invalid findings rejected")
        if invalid_paths > 0:
            reason_set.add(PolicyReason.invalid_paths)
            violations.append("invalid finding paths rejected")
        if score_card.overall_score < self.FAIL_SCORE_THRESHOLD:
            reason_set.add(PolicyReason.low_score)
            violations.append("overall score below 60")
        if real_secret_findings > 0:
            reason_set.add(PolicyReason.real_secret_exposure)
            violations.append(f"real credential/secret exposure findings present ({real_secret_findings})")
        if probable_secret_findings > 0:
            reason_set.add(PolicyReason.probable_secret_exposure)
            warnings.append(f"probable secret exposure findings present ({probable_secret_findings})")
        if private_key_findings > 0:
            reason_set.add(PolicyReason.private_key_material)
            violations.append(f"private key material findings present ({private_key_findings})")
        if baseline_real_secret_entries > 0:
            reason_set.add(PolicyReason.baseline_real_secret_prohibited)
            violations.append(f"baseline contains prohibited real-secret entries ({baseline_real_secret_entries})")
        if baseline_expired_entries > 0:
            reason_set.add(PolicyReason.baseline_entry_expired)
            warnings.append(f"baseline has expired entries ({baseline_expired_entries})")
        if baseline_missing_owner_entries > 0:
            reason_set.add(PolicyReason.baseline_entry_missing_owner)
            warnings.append(f"baseline has entries missing owner ({baseline_missing_owner_entries})")
        if baseline_expiring_soon_entries > 0:
            reason_set.add(PolicyReason.baseline_entry_expiring)
            warnings.append(f"baseline has entries expiring soon ({baseline_expiring_soon_entries})")
        if history_scan_skipped:
            reason_set.add(PolicyReason.history_scan_skipped)
            warnings.append("history scan skipped; historical secret exposure coverage is incomplete")
        if history_scan_stale:
            reason_set.add(PolicyReason.history_scan_stale)
            age = int(history_scan_age_days) if isinstance(history_scan_age_days, int) else None
            if age is None:
                warnings.append("history scan stale; historical secret exposure coverage is outdated")
            elif age >= 365:
                warnings.append(f"history scan stale ({age} days); critical refresh overdue")
            elif age >= 180:
                warnings.append(f"history scan stale ({age} days); refresh strongly recommended")
            elif age >= 90:
                warnings.append(f"history scan stale ({age} days); refresh recommended")
            elif age >= 60:
                warnings.append(f"history scan aging ({age} days)")
            else:
                warnings.append(f"history scan stale ({age} days)")
        if secret_scanner_unavailable_count > 0:
            reason_set.add(PolicyReason.secret_scanner_unavailable)
            warnings.append(f"secret scanners unavailable ({secret_scanner_unavailable_count})")

        if high_security_findings > self.HIGH_SECURITY_FINDINGS_WARN_THRESHOLD:
            reason_set.add(PolicyReason.high_security_findings)
            warnings.append(
                "high security findings exceed threshold "
                f"({high_security_findings} > {self.HIGH_SECURITY_FINDINGS_WARN_THRESHOLD})"
            )
        if score_card.overall_score < self.WARN_SCORE_THRESHOLD:
            reason_set.add(PolicyReason.low_score)
            warnings.append("overall score below 80")

        reasons = [reason for reason in self._REASON_ORDER if reason in reason_set]

        if violations:
            return QualityPolicyResult(
                status=PolicyStatus.fail,
                reasons=reasons,
                violations=violations,
                warnings=warnings,
                summary="Quality policy failed",
            )
        if warnings:
            return QualityPolicyResult(
                status=PolicyStatus.warn,
                reasons=reasons,
                violations=[],
                warnings=warnings,
                summary="Quality policy warning",
            )
        return QualityPolicyResult(
            status=PolicyStatus.pass_,
            reasons=[],
            violations=[],
            warnings=[],
            summary="Quality policy passed",
        )
