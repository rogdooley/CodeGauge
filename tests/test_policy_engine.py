from __future__ import annotations

from codegauge.domain.models import Severity
from codegauge.policy import CodeGaugePolicyEngine, PolicyReason, PolicyStatus
from codegauge.scoring.engine import CodeGaugeScoringEngine
from codegauge.scoring.models import NormalizedMetric, ScoreCategory


def _score_card(overall_metrics: list[NormalizedMetric]):
    return CodeGaugeScoringEngine().score(overall_metrics)


def test_policy_fails_on_critical_security() -> None:
    engine = CodeGaugePolicyEngine()
    metrics = [
        NormalizedMetric(
            category=ScoreCategory.security,
            severity=Severity.critical,
            count=1,
            score_hint=1.0,
            source="bandit",
        )
    ]
    policy = engine.evaluate(
        score_card=_score_card(metrics),
        metrics=metrics,
        scanner_failures=0,
        parser_missing=0,
        invalid_findings=0,
        invalid_paths=0,
    )
    assert policy.status == PolicyStatus.fail
    assert policy.reasons == [PolicyReason.critical_security_finding]
    assert any("critical security" in item for item in policy.violations)


def test_policy_fails_on_operational_counters() -> None:
    engine = CodeGaugePolicyEngine()
    metrics: list[NormalizedMetric] = []
    policy = engine.evaluate(
        score_card=_score_card(metrics),
        metrics=metrics,
        scanner_failures=1,
        parser_missing=1,
        invalid_findings=1,
        invalid_paths=1,
    )
    assert policy.status == PolicyStatus.fail
    assert policy.reasons == [
        PolicyReason.scanner_failure,
        PolicyReason.parser_missing,
        PolicyReason.invalid_findings,
        PolicyReason.invalid_paths,
    ]
    assert any("scanner failures" in item for item in policy.violations)
    assert any("parser registrations missing" in item for item in policy.violations)
    assert any("invalid findings" in item for item in policy.violations)


def test_policy_warns_for_high_findings_and_score_below_80() -> None:
    engine = CodeGaugePolicyEngine()
    metrics = [
        NormalizedMetric(
            category=ScoreCategory.security,
            severity=Severity.high,
            count=4,
            score_hint=1.0,
            source="bandit",
        )
    ]
    policy = engine.evaluate(
        score_card=_score_card(metrics),
        metrics=metrics,
        scanner_failures=0,
        parser_missing=0,
        invalid_findings=0,
        invalid_paths=0,
    )
    assert policy.status == PolicyStatus.warn
    assert policy.reasons == [PolicyReason.high_security_findings]
    assert any("high security findings exceed threshold" in item for item in policy.warnings)


def test_policy_passes_when_no_fail_or_warn_conditions() -> None:
    engine = CodeGaugePolicyEngine()
    metrics: list[NormalizedMetric] = []
    policy = engine.evaluate(
        score_card=_score_card(metrics),
        metrics=metrics,
        scanner_failures=0,
        parser_missing=0,
        invalid_findings=0,
        invalid_paths=0,
    )
    assert policy.status == PolicyStatus.pass_
    assert policy.reasons == []
    assert policy.violations == []
    assert policy.warnings == []


def test_policy_warns_on_baseline_governance_issues() -> None:
    engine = CodeGaugePolicyEngine()
    metrics: list[NormalizedMetric] = []
    policy = engine.evaluate(
        score_card=_score_card(metrics),
        metrics=metrics,
        scanner_failures=0,
        parser_missing=0,
        invalid_findings=0,
        invalid_paths=0,
        baseline_expired_entries=2,
        baseline_missing_owner_entries=1,
        baseline_expiring_soon_entries=3,
    )
    assert policy.status == PolicyStatus.warn
    assert policy.reasons == [
        PolicyReason.baseline_entry_expired,
        PolicyReason.baseline_entry_missing_owner,
        PolicyReason.baseline_entry_expiring,
    ]
    assert any("expired entries" in item for item in policy.warnings)
    assert any("missing owner" in item for item in policy.warnings)
    assert any("expiring soon" in item for item in policy.warnings)


def test_policy_engine_is_deterministic() -> None:
    engine = CodeGaugePolicyEngine()
    metrics = [
        NormalizedMetric(
            category=ScoreCategory.security,
            severity=Severity.high,
            count=2,
            score_hint=1.0,
            source="bandit",
        )
    ]
    score_card = _score_card(metrics)
    first = engine.evaluate(
        score_card=score_card,
        metrics=metrics,
        scanner_failures=0,
        parser_missing=0,
        invalid_findings=0,
        invalid_paths=0,
    )
    second = engine.evaluate(
        score_card=score_card,
        metrics=metrics,
        scanner_failures=0,
        parser_missing=0,
        invalid_findings=0,
        invalid_paths=0,
    )
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_policy_reason_order_is_deterministic() -> None:
    engine = CodeGaugePolicyEngine()
    metrics = [
        NormalizedMetric(
            category=ScoreCategory.security,
            severity=Severity.critical,
            count=1,
            score_hint=1.0,
            source="bandit",
        ),
        NormalizedMetric(
            category=ScoreCategory.security,
            severity=Severity.high,
            count=10,
            score_hint=1.0,
            source="bandit",
        ),
    ]
    policy = engine.evaluate(
        score_card=_score_card(metrics),
        metrics=metrics,
        scanner_failures=1,
        parser_missing=1,
        invalid_findings=1,
        invalid_paths=1,
    )
    assert policy.reasons == [
        PolicyReason.scanner_failure,
        PolicyReason.parser_missing,
        PolicyReason.invalid_findings,
        PolicyReason.invalid_paths,
        PolicyReason.critical_security_finding,
        PolicyReason.high_security_findings,
        PolicyReason.low_score,
    ]


def test_policy_fails_for_secrets_specific_reasons() -> None:
    engine = CodeGaugePolicyEngine()
    policy = engine.evaluate(
        score_card=_score_card([]),
        metrics=[],
        scanner_failures=0,
        parser_missing=0,
        invalid_findings=0,
        invalid_paths=0,
        real_secret_findings=2,
        private_key_findings=1,
        baseline_real_secret_entries=1,
    )
    assert policy.status == PolicyStatus.fail
    assert policy.reasons == [
        PolicyReason.real_secret_exposure,
        PolicyReason.private_key_material,
        PolicyReason.baseline_real_secret_prohibited,
    ]


def test_policy_warns_for_history_skipped_and_secret_scanner_unavailable() -> None:
    engine = CodeGaugePolicyEngine()
    policy = engine.evaluate(
        score_card=_score_card([]),
        metrics=[],
        scanner_failures=0,
        parser_missing=0,
        invalid_findings=0,
        invalid_paths=0,
        history_scan_skipped=True,
        secret_scanner_unavailable_count=2,
    )
    assert policy.status == PolicyStatus.warn
    assert policy.reasons == [
        PolicyReason.history_scan_skipped,
        PolicyReason.secret_scanner_unavailable,
    ]


def test_policy_warns_for_probable_secret_exposure_only() -> None:
    engine = CodeGaugePolicyEngine()
    policy = engine.evaluate(
        score_card=_score_card([]),
        metrics=[],
        scanner_failures=0,
        parser_missing=0,
        invalid_findings=0,
        invalid_paths=0,
        probable_secret_findings=2,
    )
    assert policy.status == PolicyStatus.warn
    assert PolicyReason.probable_secret_exposure in policy.reasons
    assert all("real credential/secret" not in item for item in policy.violations)


def test_policy_fails_when_real_and_probable_secret_exposure_present() -> None:
    engine = CodeGaugePolicyEngine()
    policy = engine.evaluate(
        score_card=_score_card([]),
        metrics=[],
        scanner_failures=0,
        parser_missing=0,
        invalid_findings=0,
        invalid_paths=0,
        probable_secret_findings=3,
        real_secret_findings=1,
    )
    assert policy.status == PolicyStatus.fail
    assert PolicyReason.real_secret_exposure in policy.reasons
    assert PolicyReason.probable_secret_exposure in policy.reasons
