from __future__ import annotations

import re
from collections.abc import Sequence
from enum import StrEnum

from ..domain.models import Category, Finding, ScanResult

_RUNTIME_PREFIXES = ("src/", "app/", "services/", "api/", "middleware/")
_TOOLING_PREFIXES = ("tools/", "scripts/", "dev/", "maintenance/")
_DOCUMENTATION_PREFIXES = ("docs/", "documentation/", "designdocuments/", "readme/")
_FALSE_POSITIVE_B105_LITERALS = {"", '""', "(", ")", "NOT", "AND", "OR"}


class ClassificationReason(StrEnum):
    NON_SECURITY_CATEGORY = "non_security_category"
    PATH_RUNTIME = "path_runtime"
    PATH_TOOLING = "path_tooling"
    PATH_TEST = "path_test"
    PATH_DOCUMENTATION = "path_documentation"
    BANDIT_B105_TOKEN_LITERAL = "bandit_b105_token_literal"
    BANDIT_B404_TOOL_SUBPROCESS = "bandit_b404_tool_subprocess"
    BANDIT_B603_TOOL_SUBPROCESS = "bandit_b603_tool_subprocess"
    BANDIT_B603_SHELL_TRUE = "bandit_b603_shell_true"
    BANDIT_B310_TEST_URL_OPEN = "bandit_b310_test_urlopen"
    HEURISTIC_INTERPOLATED_COMMAND = "heuristic_interpolated_command"
    DEFAULT_UNKNOWN = "default_unknown"


class SecurityFindingClassifier:
    CLASSIFIER_NAME = "security_classifier"
    CLASSIFIER_VERSION = "1.0.0"
    RULESET = "default"
    SECURITY_CLASSES = (
        "runtime_security",
        "tooling_security",
        "test_security",
        "false_positive",
        "unknown",
    )
    SECURITY_CONTEXTS = (
        "runtime",
        "tool",
        "test",
        "config",
        "dependency",
        "unknown",
    )
    REASON_CODES = (
        ClassificationReason.PATH_RUNTIME.value,
        ClassificationReason.PATH_TOOLING.value,
        ClassificationReason.PATH_TEST.value,
        ClassificationReason.PATH_DOCUMENTATION.value,
        ClassificationReason.BANDIT_B105_TOKEN_LITERAL.value,
        ClassificationReason.BANDIT_B404_TOOL_SUBPROCESS.value,
        ClassificationReason.BANDIT_B603_TOOL_SUBPROCESS.value,
        ClassificationReason.BANDIT_B603_SHELL_TRUE.value,
        ClassificationReason.BANDIT_B310_TEST_URL_OPEN.value,
        ClassificationReason.HEURISTIC_INTERPOLATED_COMMAND.value,
        ClassificationReason.DEFAULT_UNKNOWN.value,
    )

    @classmethod
    def provenance(cls) -> dict[str, str]:
        return {
            "name": cls.CLASSIFIER_NAME,
            "version": cls.CLASSIFIER_VERSION,
            "ruleset": cls.RULESET,
        }

    @classmethod
    def contract(cls) -> dict[str, object]:
        return {
            "classifier": cls.provenance(),
            "reason_codes": list(cls.REASON_CODES),
            "security_classes": list(cls.SECURITY_CLASSES),
            "security_contexts": list(cls.SECURITY_CONTEXTS),
        }

    def classify_scan_results(self, results: Sequence[ScanResult]) -> list[ScanResult]:
        classified: list[ScanResult] = []
        for result in results:
            if not result.success:
                classified.append(result)
                continue
            classified_findings = [self.classify_finding(finding) for finding in result.findings]
            classified.append(result.model_copy(update={"findings": classified_findings}))
        return classified

    def classify_finding(self, finding: Finding) -> Finding:
        if finding.category != Category.security:
            return finding.model_copy(
                update={
                    "security_class": "not_security",
                    "security_context": "unknown",
                    "security_impact": "none",
                    "score_weight": 1.0,
                    "classification_reason": ClassificationReason.NON_SECURITY_CATEGORY.value,
                    "classification_rule_id": ClassificationReason.NON_SECURITY_CATEGORY.value,
                    "classification_detail": None,
                }
            )

        path = finding.file.as_posix().lower()
        rule_id = finding.rule_id.upper()
        message = finding.message
        raw_text = f"{message}\n{finding.raw_payload}".lower()

        # Bandit B105 string-token false positives.
        if finding.tool == "bandit" and rule_id == "B105":
            literal = self._extract_b105_literal(message)
            if literal in _FALSE_POSITIVE_B105_LITERALS:
                return finding.model_copy(
                    update={
                        "security_class": "false_positive",
                        "security_context": "unknown",
                        "security_impact": "none",
                        "score_weight": 0.0,
                        "classification_reason": ClassificationReason.BANDIT_B105_TOKEN_LITERAL.value,
                        "classification_rule_id": ClassificationReason.BANDIT_B105_TOKEN_LITERAL.value,
                        "classification_detail": f"suspicious literal token: {literal}",
                    }
                )

        if self._is_test_path(path):
            # Bandit B310 explicit test-path down-weighting.
            if finding.tool == "bandit" and rule_id == "B310":
                return finding.model_copy(
                    update={
                        "security_class": "test_security",
                        "security_context": "test",
                        "security_impact": "low",
                        "score_weight": 0.1,
                        "classification_reason": ClassificationReason.BANDIT_B310_TEST_URL_OPEN.value,
                        "classification_rule_id": ClassificationReason.BANDIT_B310_TEST_URL_OPEN.value,
                        "classification_detail": None,
                    }
                )
            return finding.model_copy(
                update={
                    "security_class": "test_security",
                    "security_context": "test",
                    "security_impact": "low",
                    "score_weight": 0.1,
                    "classification_reason": ClassificationReason.PATH_TEST.value,
                    "classification_rule_id": ClassificationReason.PATH_TEST.value,
                    "classification_detail": None,
                }
            )

        if self._is_documentation_path(path):
            return finding.model_copy(
                update={
                    "security_class": "false_positive",
                    "security_context": "unknown",
                    "security_impact": "none",
                    "score_weight": 0.0,
                    "classification_reason": ClassificationReason.PATH_DOCUMENTATION.value,
                    "classification_rule_id": ClassificationReason.PATH_DOCUMENTATION.value,
                    "classification_detail": None,
                }
            )

        if self._is_tooling_path(path):
            if finding.tool == "bandit" and rule_id in {"B404", "B603"}:
                escalation_reason = self._escalation_reason(raw_text, rule_id)
                if escalation_reason is not None:
                    return finding.model_copy(
                        update={
                            "security_class": "runtime_security",
                            "security_context": "runtime",
                            "security_impact": "high",
                            "score_weight": 1.0,
                            "classification_reason": escalation_reason.value,
                            "classification_rule_id": escalation_reason.value,
                            "classification_detail": (
                                "tooling path escalated due to command execution exploitability signals"
                            ),
                        }
                    )
                return finding.model_copy(
                    update={
                        "security_class": "tooling_security",
                        "security_context": "tool",
                        "security_impact": "medium",
                        "score_weight": 0.25,
                        "classification_reason": (
                            ClassificationReason.BANDIT_B404_TOOL_SUBPROCESS.value
                            if rule_id == "B404"
                            else ClassificationReason.BANDIT_B603_TOOL_SUBPROCESS.value
                        ),
                        "classification_rule_id": (
                            ClassificationReason.BANDIT_B404_TOOL_SUBPROCESS.value
                            if rule_id == "B404"
                            else ClassificationReason.BANDIT_B603_TOOL_SUBPROCESS.value
                        ),
                        "classification_detail": None,
                    }
                )
            return finding.model_copy(
                update={
                    "security_class": "tooling_security",
                    "security_context": "tool",
                    "security_impact": "medium",
                    "score_weight": 0.25,
                    "classification_reason": ClassificationReason.PATH_TOOLING.value,
                    "classification_rule_id": ClassificationReason.PATH_TOOLING.value,
                    "classification_detail": None,
                }
            )

        if any(path.startswith(prefix) for prefix in _RUNTIME_PREFIXES):
            return finding.model_copy(
                update={
                    "security_class": "runtime_security",
                    "security_context": "runtime",
                    "security_impact": "high",
                    "score_weight": 1.0,
                    "classification_reason": ClassificationReason.PATH_RUNTIME.value,
                    "classification_rule_id": ClassificationReason.PATH_RUNTIME.value,
                    "classification_detail": None,
                }
            )

        return finding.model_copy(
            update={
                "security_class": "unknown",
                "security_context": "unknown",
                "security_impact": "medium",
                "score_weight": 1.0,
                "classification_reason": ClassificationReason.DEFAULT_UNKNOWN.value,
                "classification_rule_id": ClassificationReason.DEFAULT_UNKNOWN.value,
                "classification_detail": "no explicit path/rule heuristic matched",
            }
        )

    @staticmethod
    def _is_test_path(path: str) -> bool:
        return path.startswith("tests/") or path.endswith("/smoke_test.py") or path.endswith("smoke_test.py")

    @staticmethod
    def _is_tooling_path(path: str) -> bool:
        return any(path.startswith(prefix) for prefix in _TOOLING_PREFIXES)

    @staticmethod
    def _is_documentation_path(path: str) -> bool:
        return path in {"readme", "readme.md"} or any(path.startswith(prefix) for prefix in _DOCUMENTATION_PREFIXES)

    @staticmethod
    def _extract_b105_literal(message: str) -> str | None:
        single = re.search(r"'([^']*)'", message)
        if single:
            return single.group(1)
        double = re.search(r'"([^"]*)"', message)
        if double:
            return double.group(1)
        return None

    @staticmethod
    def _escalation_reason(raw_text: str, rule_id: str) -> ClassificationReason | None:
        shell_true = "shell=true" in raw_text or "shell = true" in raw_text
        if shell_true and rule_id == "B603":
            return ClassificationReason.BANDIT_B603_SHELL_TRUE

        if "os.system(" in raw_text or "subprocess.popen(" in raw_text:
            return ClassificationReason.HEURISTIC_INTERPOLATED_COMMAND

        interpolation_patterns = [
            r"\{.*input.*\}",
            r"\{[a-zA-Z_][a-zA-Z0-9_\.]*\}",
            r"%\s*\w+",
            r"\.format\(",
            r"\bf['\"]",
            r"run\s*\(\s*f['\"]",
            r"sys\.argv",
            r"request\.",
            r"input\(",
        ]
        interpolated = any(re.search(pattern, raw_text) for pattern in interpolation_patterns)
        if interpolated:
            return ClassificationReason.HEURISTIC_INTERPOLATED_COMMAND
        return None
