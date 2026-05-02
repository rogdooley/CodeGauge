from __future__ import annotations

from codegauge.services.recommendation_engine import RecommendationEngine, strip_internal_scores


def _finding(
    *,
    rule_id: str,
    category: str,
    severity: str,
    file: str,
    message: str,
    confidence: float = 0.9,
    tool: str = "test",
    security_class: str | None = None,
) -> dict[str, object]:
    return {
        "tool": tool,
        "rule_id": rule_id,
        "severity": severity,
        "category": category,
        "file": file,
        "message": message,
        "normalized_message": message.lower(),
        "confidence": confidence,
        "security_class": security_class,
    }


def test_clustering_groups_related_findings() -> None:
    engine = RecommendationEngine()
    findings = [
        _finding(rule_id="F401", category="dead_code", severity="low", file="src/a.py", message="unused import x"),
        _finding(rule_id="F402", category="dead_code", severity="low", file="src/b.py", message="unused import y"),
    ]

    clusters = engine.cluster_findings(findings)
    assert len(clusters) == 1
    assert len(clusters[0].findings) == 2


def test_deterministic_ranking_and_top_cap() -> None:
    engine = RecommendationEngine()
    findings = []
    for i in range(12):
        findings.append(_finding(rule_id="AUTH001", category="security", severity="high", file=f"api/r{i}.py", message="missing auth guard"))
    for i in range(6):
        findings.append(_finding(rule_id="C901", category="complexity", severity="medium", file=f"core/m{i}.py", message="function too complex"))
    for i in range(6):
        findings.append(_finding(rule_id="F401", category="dead_code", severity="low", file=f"src/u{i}.py", message="unused import z"))

    plan = strip_internal_scores(
        engine.generate(
            findings=findings,
            metrics={},
            project_summary={"score_card": {"overall_score": 72.0}},
            previous_run_summary=None,
        )
    )

    assert len(plan["top_recommendations"]) <= 5
    assert plan["top_recommendations"][0]["category"] == "Security"


def test_mixed_category_selection_not_quota_based() -> None:
    engine = RecommendationEngine()
    findings = []
    findings.extend([
        _finding(rule_id="AUTH001", category="security", severity="high", file=f"api/{i}.py", message="missing auth guard")
        for i in range(8)
    ])
    findings.extend([
        _finding(rule_id="C901", category="complexity", severity="medium", file=f"mod/{i}.py", message="function too complex")
        for i in range(8)
    ])

    plan = strip_internal_scores(engine.generate(findings=findings, metrics={}, project_summary={}, previous_run_summary=None))
    cats = {item["category"] for item in plan["top_recommendations"]}
    assert "Security" in cats
    assert "Complexity" in cats


def test_quick_wins_cap() -> None:
    engine = RecommendationEngine()
    findings = [
        _finding(rule_id=f"F40{i}", category="dead_code", severity="low", file=f"src/a{i}.py", message="unused import x")
        for i in range(20)
    ]
    plan = strip_internal_scores(engine.generate(findings=findings, metrics={}, project_summary={}, previous_run_summary=None))
    assert len(plan["quick_wins"]) <= 10


def test_systemic_issue_detection() -> None:
    engine = RecommendationEngine()
    findings = [
        _finding(rule_id="ANN001", category="typing", severity="medium", file=f"pkg/m{i}.py", message="missing type hint")
        for i in range(20)
    ]
    plan = strip_internal_scores(engine.generate(findings=findings, metrics={}, project_summary={}, previous_run_summary=None))
    assert len(plan["systemic_issues"]) == 1


def test_stable_ordering() -> None:
    engine = RecommendationEngine()
    findings = [
        _finding(rule_id="AUTH001", category="security", severity="high", file="api/a.py", message="missing auth guard"),
        _finding(rule_id="AUTH001", category="security", severity="high", file="api/b.py", message="missing auth guard"),
        _finding(rule_id="F401", category="dead_code", severity="low", file="src/a.py", message="unused import"),
    ]
    p1 = strip_internal_scores(engine.generate(findings=findings, metrics={}, project_summary={}, previous_run_summary=None))
    p2 = strip_internal_scores(engine.generate(findings=list(reversed(findings)), metrics={}, project_summary={}, previous_run_summary=None))
    assert p1 == p2


def test_versions_provenance_and_empty_sections_are_emitted() -> None:
    engine = RecommendationEngine()
    plan = strip_internal_scores(
        engine.generate(
            findings=[],
            metrics={},
            project_summary={"schema_version": "2.0.0"},
            previous_run_summary=None,
        )
    )
    assert plan["schema_version"] == "1.0.0"
    assert plan["recommendation_engine_version"] == "1"
    assert plan["ruleset_version"] == "1"
    assert plan["generated_from"]["findings_count"] == 0
    assert plan["generated_from"]["clusters_count"] == 0
    assert plan["generated_from"]["source_schema_version"] == "2.0.0"
    assert plan["top_recommendations"] == []
    assert plan["quick_wins"] == []
    assert plan["architectural_concerns"] == []
    assert plan["security_concerns"] == []
    assert plan["systemic_issues"] == []


def test_runtime_medium_beats_high_noise_lint() -> None:
    engine = RecommendationEngine()
    findings = [
        _finding(
            rule_id="AUTH001",
            category="security",
            severity="medium",
            file="api/auth.py",
            message="missing auth guard",
            confidence=0.95,
            tool="bandit",
            security_class="runtime_security",
        ),
        _finding(
            rule_id="LINT001",
            category="lint",
            severity="high",
            file="src/app.py",
            message="style rule violation",
            confidence=0.2,
            tool="ruff",
        ),
    ]

    plan = strip_internal_scores(engine.generate(findings=findings, metrics={}, project_summary={}, previous_run_summary=None))
    assert plan["top_recommendations"][0]["category"] == "Security"
    assert "Medium security" in plan["top_recommendations"][0]["why"]


def test_clustered_medium_outranks_isolated_low() -> None:
    engine = RecommendationEngine()
    findings = [
        _finding(
            rule_id="ANN001",
            category="typing",
            severity="medium",
            file=f"pkg/m{i}.py",
            message="missing return type annotation",
            confidence=0.95,
            tool="pyright",
        )
        for i in range(10)
    ]
    findings.append(
        _finding(
            rule_id="F401",
            category="dead_code",
            severity="low",
            file="src/one.py",
            message="unused import x",
            confidence=0.95,
            tool="ruff",
        )
    )

    plan = strip_internal_scores(engine.generate(findings=findings, metrics={}, project_summary={}, previous_run_summary=None))
    assert "Medium typing" in plan["top_recommendations"][0]["why"]
    assert plan["top_recommendations"][0]["supporting_findings_count"] == 10


def test_noisy_false_positive_is_deprioritized() -> None:
    engine = RecommendationEngine()
    findings = [
        _finding(
            rule_id="B105",
            category="security",
            severity="high",
            file="src/settings.py",
            message="possible hardcoded password string",
            confidence=0.9,
            tool="bandit",
            security_class="false_positive",
        ),
        _finding(
            rule_id="AUTH001",
            category="security",
            severity="high",
            file="api/views.py",
            message="missing auth guard",
            confidence=0.95,
            tool="bandit",
            security_class="runtime_security",
        ),
    ]

    plan = strip_internal_scores(engine.generate(findings=findings, metrics={}, project_summary={}, previous_run_summary=None))
    first = plan["top_recommendations"][0]
    last = plan["top_recommendations"][-1]
    assert first["priority_reason"].split("|")[0] == "runtime_security"
    assert last["priority_reason"].split("|")[0] == "false_positive_security"


def test_deterministic_tie_break_uses_title_after_severity_and_count() -> None:
    engine = RecommendationEngine()
    findings = [
        _finding(rule_id="A100", category="alpha", severity="low", file="src/alpha.py", message="alpha issue", confidence=0.95),
        _finding(rule_id="Z100", category="zeta", severity="low", file="src/zeta.py", message="zeta issue", confidence=0.95),
    ]

    plan = strip_internal_scores(engine.generate(findings=findings, metrics={}, project_summary={}, previous_run_summary=None))
    titles = [item["title"] for item in plan["top_recommendations"]]
    assert titles[:2] == ["Low alpha issue pattern", "Low zeta issue pattern"]
