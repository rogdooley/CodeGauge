from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, Sequence


_SEVERITY_WEIGHTS = {
    "critical": 100.0,
    "high": 40.0,
    "medium": 10.0,
    "low": 2.0,
    "info": 0.5,
}

_SECURITY_EXPLOITABILITY = {
    "runtime": 2.5,
    "tooling": 0.5,
    "test_only": 0.25,
    "false_positive": 0.1,
}

_NON_SECURITY_EXPLOITABILITY = {
    "typing": 1.2,
    "lint": 0.5,
    "dead_code": 0.3,
    "maintainability": 0.6,
    "default": 0.6,
}

_KNOWN_NOISY_RULES = {"bandit:b105", "b105"}
_LIKELY_HEURISTIC_RULES = {"bandit:b104", "bandit:b108", "b104", "b108"}
_STRONG_SIGNAL_FAMILIES = {"pyright", "mypy", "typescript", "tsc"}


def severity_weight(severity: str) -> float:
    return _SEVERITY_WEIGHTS.get(str(severity or "info").lower(), _SEVERITY_WEIGHTS["info"])


def prevalence_weight(finding_count: int) -> float:
    count = int(finding_count or 0)
    if count <= 1:
        return 1.0
    if count <= 4:
        return 1.2
    if count <= 9:
        return 1.5
    if count <= 24:
        return 2.0
    return 3.0


def exploitability_weight(category: str, findings: Sequence[Mapping[str, Any]]) -> float:
    normalized = str(category or "").lower()
    if normalized == "security":
        security_class = _dominant_security_class(findings)
        return _SECURITY_EXPLOITABILITY[security_class]
    return _NON_SECURITY_EXPLOITABILITY.get(normalized, _NON_SECURITY_EXPLOITABILITY["default"])


def confidence_weight(findings: Sequence[Mapping[str, Any]]) -> float:
    if not findings:
        return 1.0

    values: list[float] = []
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "").strip().lower()
        tool = str(finding.get("tool") or "").strip().lower()
        combined_rule = f"{tool}:{rule_id}" if tool else rule_id

        if combined_rule in _KNOWN_NOISY_RULES or rule_id in _KNOWN_NOISY_RULES:
            values.append(0.25)
            continue
        if combined_rule in _LIKELY_HEURISTIC_RULES or rule_id in _LIKELY_HEURISTIC_RULES:
            values.append(0.9)
            continue
        if tool in _STRONG_SIGNAL_FAMILIES:
            values.append(1.0)
            continue

        explicit = finding.get("confidence")
        if explicit is not None:
            explicit_value = float(explicit)
            if explicit_value >= 0.85:
                values.append(1.0)
            elif explicit_value >= 0.5:
                values.append(0.5)
            else:
                values.append(0.25)
            continue

        values.append(0.5)

    if not values:
        return 1.0
    return round(sum(values) / len(values), 3)


def remediation_cost(category: str, severity: str, findings: Sequence[Mapping[str, Any]]) -> float:
    normalized = str(category or "").lower()
    files = {str(f.get("file") or "") for f in findings if str(f.get("file") or "")}
    count = len(findings)

    if normalized in {"lint", "dead_code"} and count <= 8:
        return 0.5
    if normalized == "typing" and count <= 6 and len(files) <= 2:
        return 1.0
    if normalized == "security":
        if str(severity or "").lower() == "critical" and count >= 10:
            return 5.0
        return 1.0 if count <= 4 else 2.0
    if count >= 20 or len(files) >= 8:
        return 5.0
    if count >= 6 or len(files) >= 3:
        return 2.0
    return 1.0


def compute_priority(*, severity: str, category: str, findings: Sequence[Mapping[str, Any]]) -> tuple[float, str]:
    finding_count = len(findings)
    sev_weight = severity_weight(severity)
    prev_weight = prevalence_weight(finding_count)
    explo_weight = exploitability_weight(category, findings)
    conf_weight = confidence_weight(findings)
    rem_cost = remediation_cost(category, severity, findings)

    score = (sev_weight * prev_weight * explo_weight * conf_weight) / rem_cost
    rounded = round(score, 1)
    reason = _priority_reason(
        category=category,
        findings=findings,
        prevalence=prev_weight,
        confidence=conf_weight,
        cost=rem_cost,
    )
    return rounded, reason


def _dominant_security_class(findings: Sequence[Mapping[str, Any]]) -> str:
    mapped: list[str] = []
    for finding in findings:
        security_class = str(finding.get("security_class") or "").lower()
        if security_class == "runtime_security":
            mapped.append("runtime")
        elif security_class == "tooling_security":
            mapped.append("tooling")
        elif security_class == "test_security":
            mapped.append("test_only")
        elif security_class == "false_positive":
            mapped.append("false_positive")
        else:
            mapped.append("runtime")
    if not mapped:
        return "runtime"
    return Counter(mapped).most_common(1)[0][0]


def _priority_reason(
    *,
    category: str,
    findings: Sequence[Mapping[str, Any]],
    prevalence: float,
    confidence: float,
    cost: float,
) -> str:
    normalized = str(category or "").lower()
    if normalized == "security":
        security_class = _dominant_security_class(findings)
        context = f"{security_class}_security"
    else:
        context = normalized or "maintainability"

    prevalence_label = "isolated_prevalence"
    if prevalence >= 3.0:
        prevalence_label = "very_high_prevalence"
    elif prevalence >= 2.0:
        prevalence_label = "high_prevalence"
    elif prevalence >= 1.5:
        prevalence_label = "moderate_prevalence"

    confidence_label = "medium_confidence"
    if confidence >= 0.85:
        confidence_label = "high_confidence"
    elif confidence < 0.5:
        confidence_label = "low_confidence"

    if cost <= 1.0:
        cost_label = "low_cost"
    elif cost <= 2.0:
        cost_label = "moderate_cost"
    else:
        cost_label = "high_cost"

    return "|".join((context, prevalence_label, confidence_label, cost_label))
