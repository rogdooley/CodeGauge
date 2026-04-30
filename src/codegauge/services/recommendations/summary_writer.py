from __future__ import annotations

from typing import Any, Mapping, Sequence


class RecommendationSummaryWriter:
    def write(
        self,
        *,
        top_recommendations: Sequence[Mapping[str, Any]],
        quick_wins: Sequence[Mapping[str, Any]],
        systemic_issues: Sequence[Mapping[str, Any]],
        project_summary: Mapping[str, Any],
        metrics: Mapping[str, Any],
        previous_run_summary: Mapping[str, Any] | None,
    ) -> str:
        score = float(((project_summary.get("score_card") or {}).get("overall_score", 0.0) or 0.0))
        if score >= 85:
            health = "Good"
        elif score >= 70:
            health = "Fair"
        else:
            health = "Needs Improvement"

        top = top_recommendations[0]["title"] if top_recommendations else "no critical findings"
        quick_count = len(quick_wins)
        systemic_count = len(systemic_issues)

        trend_text = ""
        if previous_run_summary:
            prev_score = float(((previous_run_summary.get("score_card") or {}).get("overall_score", 0.0) or 0.0))
            if prev_score:
                direction = "improved" if score >= prev_score else "declined"
                trend_text = f" Score has {direction} since the previous run."
        _ = metrics
        return (
            f"Project health is {health}. "
            f"The highest priority issue is {top}. "
            f"{quick_count} quick wins can be completed in under one hour. "
            f"{systemic_count} systemic maintainability concern(s) affect multiple modules."
            f"{trend_text}"
        ).strip()
