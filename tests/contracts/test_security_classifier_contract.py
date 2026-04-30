from __future__ import annotations

from codegauge.services.security_classifier import SecurityFindingClassifier


def test_security_classifier_contract_snapshot() -> None:
    expected = {
        "classifier": {
            "name": "security_classifier",
            "version": "1.0.0",
            "ruleset": "default",
        },
        "reason_codes": [
            "path_runtime",
            "path_tooling",
            "path_test",
            "bandit_b105_token_literal",
            "bandit_b404_tool_subprocess",
            "bandit_b603_tool_subprocess",
            "bandit_b603_shell_true",
            "bandit_b310_test_urlopen",
            "heuristic_interpolated_command",
            "default_unknown",
        ],
        "security_classes": [
            "runtime_security",
            "tooling_security",
            "test_security",
            "false_positive",
            "unknown",
        ],
        "security_contexts": [
            "runtime",
            "tool",
            "test",
            "config",
            "dependency",
            "unknown",
        ],
    }
    assert SecurityFindingClassifier.contract() == expected
