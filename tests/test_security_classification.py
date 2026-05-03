from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from codegauge.baseline import BaselineDocument, BaselineEntry, BaselineService
from codegauge.domain.models import Category, Finding, Language, ScanResult, Severity
from codegauge.scoring.engine import CodeGaugeScoringEngine
from codegauge.scoring.models import ScoreCategory
from codegauge.services.metrics import MetricsExtractor, finding_fingerprint
from codegauge.services.security_classifier import ClassificationReason, SecurityFindingClassifier


def _scan_result(*findings: Finding) -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        scanner_name="bandit",
        started_at=now,
        completed_at=now,
        duration_ms=10.0,
        findings=list(findings),
        success=True,
    )


def _security_finding(
    *,
    rule_id: str,
    file_path: str,
    message: str,
    raw_payload: dict | None = None,
) -> Finding:
    return Finding(
        tool="bandit",
        rule_id=rule_id,
        severity=Severity.high,
        category=Category.security,
        language=Language.python,
        file=Path(file_path),
        line=1,
        message=message,
        raw_payload=raw_payload or {},
    )


def test_b105_parser_token_literals_are_zero_weight_false_positives() -> None:
    classifier = SecurityFindingClassifier()
    finding = _security_finding(
        rule_id="B105",
        file_path="src/app.py",
        message='Possible hardcoded password: ""',
    )
    classified = classifier.classify_finding(finding)
    assert classified.security_class == "false_positive"
    assert classified.security_context == "unknown"
    assert classified.score_weight == 0.0
    assert classified.classification_reason == ClassificationReason.BANDIT_B105_TOKEN_LITERAL.value


def test_b603_in_tools_is_tooling_security_with_reduced_weight() -> None:
    classifier = SecurityFindingClassifier()
    finding = _security_finding(
        rule_id="B603",
        file_path="tools/release.py",
        message="subprocess call with shell=False",
    )
    classified = classifier.classify_finding(finding)
    assert classified.security_class == "tooling_security"
    assert classified.security_context == "tool"
    assert classified.score_weight == 0.25
    assert classified.classification_reason == ClassificationReason.BANDIT_B603_TOOL_SUBPROCESS.value


def test_b603_in_src_is_runtime_security_with_full_weight() -> None:
    classifier = SecurityFindingClassifier()
    finding = _security_finding(
        rule_id="B603",
        file_path="src/app.py",
        message="subprocess call with shell=False",
    )
    classified = classifier.classify_finding(finding)
    assert classified.security_class == "runtime_security"
    assert classified.security_context == "runtime"
    assert classified.score_weight == 1.0
    assert classified.classification_reason == ClassificationReason.PATH_RUNTIME.value


def test_b310_in_smoke_test_is_test_security_with_reduced_weight() -> None:
    classifier = SecurityFindingClassifier()
    finding = _security_finding(
        rule_id="B310",
        file_path="tests/smoke_test.py",
        message="urllib call can be unsafe",
    )
    classified = classifier.classify_finding(finding)
    assert classified.security_class == "test_security"
    assert classified.security_context == "test"
    assert classified.score_weight == 0.1
    assert classified.classification_reason == ClassificationReason.BANDIT_B310_TEST_URL_OPEN.value


def test_b603_in_tools_with_shell_true_escalates_to_runtime_security() -> None:
    classifier = SecurityFindingClassifier()
    finding = _security_finding(
        rule_id="B603",
        file_path="tools/release.py",
        message="subprocess call with shell=True",
        raw_payload={"issue_text": "subprocess.Popen('x', shell=True)"},
    )
    classified = classifier.classify_finding(finding)
    assert classified.security_class == "runtime_security"
    assert classified.score_weight == 1.0
    assert classified.classification_reason == ClassificationReason.BANDIT_B603_SHELL_TRUE.value


def test_b603_in_tools_with_os_system_escalates_to_runtime_security() -> None:
    classifier = SecurityFindingClassifier()
    finding = _security_finding(
        rule_id="B603",
        file_path="tools/release.py",
        message="os.system(cmd)",
        raw_payload={"snippet": "os.system(command)"},
    )
    classified = classifier.classify_finding(finding)
    assert classified.security_class == "runtime_security"
    assert classified.score_weight == 1.0
    assert classified.classification_reason == ClassificationReason.HEURISTIC_INTERPOLATED_COMMAND.value


def test_b603_in_tools_with_subprocess_popen_shell_true_escalates_to_runtime_security() -> None:
    classifier = SecurityFindingClassifier()
    finding = _security_finding(
        rule_id="B603",
        file_path="tools/release.py",
        message="subprocess.Popen(..., shell=True)",
        raw_payload={"snippet": "subprocess.Popen(cmd, shell=True)"},
    )
    classified = classifier.classify_finding(finding)
    assert classified.security_class == "runtime_security"
    assert classified.score_weight == 1.0
    assert classified.classification_reason in {
        ClassificationReason.BANDIT_B603_SHELL_TRUE.value,
        ClassificationReason.HEURISTIC_INTERPOLATED_COMMAND.value,
    }


def test_b603_in_tools_with_interpolated_run_fstring_escalates_to_runtime_security() -> None:
    classifier = SecurityFindingClassifier()
    finding = _security_finding(
        rule_id="B603",
        file_path="tools/release.py",
        message="run(f'curl {user_input}')",
        raw_payload={"snippet": "run(f'curl {user_input}')"},
    )
    classified = classifier.classify_finding(finding)
    assert classified.security_class == "runtime_security"
    assert classified.score_weight == 1.0
    assert classified.classification_reason == ClassificationReason.HEURISTIC_INTERPOLATED_COMMAND.value


def test_security_score_improves_when_false_positives_are_zero_weighted() -> None:
    classifier = SecurityFindingClassifier()
    extractor = MetricsExtractor()
    engine = CodeGaugeScoringEngine()
    findings = [
        _security_finding(rule_id="B603", file_path="src/app.py", message="subprocess call"),
        _security_finding(rule_id="B105", file_path="src/app.py", message='Possible hardcoded password: ""'),
    ]
    before = engine.score(extractor.extract_from_scan_results([_scan_result(*findings)], dedupe=False))
    classified_results = classifier.classify_scan_results([_scan_result(*findings)])
    after = engine.score(extractor.extract_from_scan_results(classified_results, dedupe=False))
    before_security = next(row.score for row in before.category_scores if row.category == ScoreCategory.security)
    after_security = next(row.score for row in after.category_scores if row.category == ScoreCategory.security)
    assert after_security >= before_security


def test_baseline_suppression_behavior_still_works_with_classification() -> None:
    classifier = SecurityFindingClassifier()
    baseline_service = BaselineService()
    finding = _security_finding(rule_id="B603", file_path="tools/release.py", message="subprocess call")
    classified = classifier.classify_finding(finding)
    result = _scan_result(classified)
    fingerprint = finding_fingerprint(classified, include_tool=True)
    baseline = BaselineDocument(
        entries=[
            BaselineEntry(
                fingerprint=fingerprint,
                accepted=True,
                created_at=datetime.now(UTC),
            )
        ]
    )
    applied = baseline_service.apply([result], baseline)
    assert len(applied.filtered_results[0].findings) == 0


def test_documentation_paths_are_zero_weighted() -> None:
    classifier = SecurityFindingClassifier()
    finding = _security_finding(rule_id="B602", file_path="README.md", message="potential command injection")
    classified = classifier.classify_finding(finding)
    assert classified.score_weight == 0.0
    assert classified.security_class == "false_positive"
    assert classified.classification_reason == ClassificationReason.PATH_DOCUMENTATION.value
