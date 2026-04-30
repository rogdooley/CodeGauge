from __future__ import annotations

from typing import Any, Mapping, Sequence

from .categorizer import RecommendationCategorizer
from .clusterer import RecommendationClusterer
from .ranker import RecommendationRanker
from .summary_writer import RecommendationSummaryWriter


class RecommendationEngine:
    schema_version = "1.0.0"
    recommendation_engine_version = "1"
    ruleset_version = "1"

    def __init__(self) -> None:
        self.clusterer = RecommendationClusterer()
        self.ranker = RecommendationRanker()
        self.categorizer = RecommendationCategorizer(self.ranker)
        self.summary_writer = RecommendationSummaryWriter()

    def generate(
        self,
        *,
        findings: Sequence[Mapping[str, Any]],
        metrics: Mapping[str, Any],
        project_summary: Mapping[str, Any],
        previous_run_summary: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        clusters = self.clusterer.cluster(findings)
        ranked = self.ranker.rank(clusters)

        top_recommendations = self.categorizer.top_recommendations(ranked)
        quick_wins = self.categorizer.quick_wins(ranked)
        security = self.categorizer.security_concerns(ranked)
        architectural = self.categorizer.architectural_concerns(ranked)
        systemic = self.categorizer.systemic_issues(clusters)

        return {
            "schema_version": self.schema_version,
            "recommendation_engine_version": self.recommendation_engine_version,
            "ruleset_version": self.ruleset_version,
            "generated_from": {
                "findings_count": len(findings),
                "clusters_count": len(clusters),
                "source_schema_version": str(project_summary.get("schema_version") or "unknown"),
            },
            "executive_summary": self.summary_writer.write(
                top_recommendations=top_recommendations,
                quick_wins=quick_wins,
                systemic_issues=systemic,
                project_summary=project_summary,
                metrics=metrics,
                previous_run_summary=previous_run_summary,
            ),
            "top_recommendations": top_recommendations,
            "quick_wins": quick_wins,
            "architectural_concerns": architectural,
            "security_concerns": security,
            "systemic_issues": systemic,
        }

    def cluster_findings(self, findings: Sequence[Mapping[str, Any]]):
        return self.clusterer.cluster(findings)


def strip_internal_scores(action_plan: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(action_plan)
    for key in (
        "top_recommendations",
        "quick_wins",
        "architectural_concerns",
        "security_concerns",
        "systemic_issues",
    ):
        cleaned: list[dict[str, Any]] = []
        for item in payload.get(key, []):
            row = dict(item)
            row.pop("_score", None)
            cleaned.append(row)
        payload[key] = cleaned
    return payload
