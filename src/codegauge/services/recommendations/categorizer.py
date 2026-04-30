from __future__ import annotations

from typing import Any, Mapping, Sequence

from .models import FindingCluster
from .ranker import RecommendationRanker

_QUICK_WIN_RULE_HINTS = (
    "unused",
    "import",
    "dead",
    "type hint",
    "format",
)


class RecommendationCategorizer:
    def __init__(self, ranker: RecommendationRanker) -> None:
        self.ranker = ranker

    def top_recommendations(self, ranked: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        return list(ranked[:5])

    def quick_wins(self, ranked: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        return [item for item in ranked if item["effort"] == "Small" and self._is_quick_win(item)][:10]

    @staticmethod
    def security_concerns(ranked: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        return [item for item in ranked if str(item["category"]).lower() == "security"][:5]

    @staticmethod
    def architectural_concerns(ranked: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        return [item for item in ranked if str(item["category"]).lower() in {"complexity", "maintainability", "typing"}][:5]

    def systemic_issues(self, clusters: Sequence[FindingCluster]) -> list[dict[str, Any]]:
        widespread = [
            cluster
            for cluster in clusters
            if len({str(f.get("file") or "") for f in cluster.findings if str(f.get("file") or "")}) >= 5
            or len(cluster.findings) >= 10
        ]
        if not widespread:
            return []

        findings: list[Mapping[str, Any]] = []
        for cluster in widespread:
            findings.extend(cluster.findings)
        synthesized = FindingCluster(key=("maintainability", "systemic", "repeated-pattern", "project"), findings=tuple(findings))
        rec = self.ranker.build_recommendation(synthesized)
        rec["title"] = "Repeated issue patterns across modules"
        rec["recommended_fix"] = "Create one remediation checklist and apply it consistently across affected modules."
        rec.pop("_score", None)
        return [rec]

    @staticmethod
    def _is_quick_win(recommendation: Mapping[str, Any]) -> bool:
        title = str(recommendation.get("title") or "").lower()
        fix = str(recommendation.get("recommended_fix") or "").lower()
        return any(hint in title or hint in fix for hint in _QUICK_WIN_RULE_HINTS)
