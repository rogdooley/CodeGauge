from __future__ import annotations

from typing import Any, Mapping, Sequence

from .models import FindingCluster

_SEVERITY_WEIGHT = {
    "critical": 100,
    "high": 70,
    "medium": 40,
    "low": 10,
    "info": 1,
}

_BLAST_RADIUS_WEIGHT = {
    "single_line": 5,
    "single_file": 15,
    "multi_file": 30,
    "systemic": 50,
}

_CONFIDENCE_WEIGHT = {
    "high": 20,
    "medium": 10,
    "low": 0,
}

_EFFORT_PENALTY = {
    "small": -5,
    "medium": -15,
    "large": -30,
    "huge": -50,
}


class RecommendationRanker:
    def rank(self, clusters: Sequence[FindingCluster]) -> list[dict[str, Any]]:
        ranked = [self.build_recommendation(cluster) for cluster in clusters]
        ranked.sort(key=self.recommendation_sort_key)
        return ranked

    def build_recommendation(self, cluster: FindingCluster) -> dict[str, Any]:
        findings = list(cluster.findings)
        severity = self._dominant_severity(findings)
        category = cluster.key[0]
        blast_radius = self._blast_radius(findings)
        confidence = self._confidence_level(findings)
        effort = self._effort(category=category, severity=severity, findings=findings)
        score = (
            _SEVERITY_WEIGHT[severity]
            + _BLAST_RADIUS_WEIGHT[blast_radius]
            + _CONFIDENCE_WEIGHT[confidence]
            + _EFFORT_PENALTY[effort]
        )

        files = sorted({str(f.get("file") or "") for f in findings if str(f.get("file") or "")})
        title = self._title_for_cluster(cluster, severity)
        where = files[0] if files else "project-wide"

        return {
            "title": title,
            "priority": self._priority_label(score),
            "category": self._category_label(category),
            "why": self._why_text(category=category, severity=severity, blast_radius=blast_radius),
            "where": where,
            "recommended_fix": self._recommended_fix(cluster),
            "effort": effort.capitalize(),
            "impact": self._impact_label(severity, blast_radius),
            "supporting_findings_count": len(findings),
            "example_files": files[:3],
            "_score": score,
        }

    @staticmethod
    def recommendation_sort_key(recommendation: Mapping[str, Any]) -> tuple[Any, ...]:
        return (
            -int(recommendation.get("_score", 0) or 0),
            -int(recommendation.get("supporting_findings_count", 0) or 0),
            str(recommendation.get("category") or ""),
            str(recommendation.get("title") or ""),
        )

    @staticmethod
    def _dominant_severity(findings: Sequence[Mapping[str, Any]]) -> str:
        best = "info"
        best_weight = -1
        for finding in findings:
            severity = str(finding.get("severity") or "info").lower()
            weight = _SEVERITY_WEIGHT.get(severity, 1)
            if weight > best_weight:
                best_weight = weight
                best = severity
        return best

    @staticmethod
    def _blast_radius(findings: Sequence[Mapping[str, Any]]) -> str:
        files = {str(f.get("file") or "") for f in findings if str(f.get("file") or "")}
        if len(files) >= 8 or len(findings) >= 20:
            return "systemic"
        if len(files) >= 3:
            return "multi_file"
        if len(files) == 1:
            return "single_file"
        return "single_line"

    @staticmethod
    def _confidence_level(findings: Sequence[Mapping[str, Any]]) -> str:
        values = [float(f.get("confidence", 1.0) or 0.0) for f in findings]
        avg = sum(values) / len(values) if values else 1.0
        if avg >= 0.8:
            return "high"
        if avg >= 0.5:
            return "medium"
        return "low"

    @staticmethod
    def _effort(*, category: str, severity: str, findings: Sequence[Mapping[str, Any]]) -> str:
        count = len(findings)
        if category in {"dead_code", "lint", "typing"} and count <= 8 and severity in {"low", "info", "medium"}:
            return "small"
        if count >= 20:
            return "huge"
        if severity == "critical" or category == "security":
            return "large" if count >= 5 else "medium"
        if count >= 10:
            return "large"
        return "medium"

    @staticmethod
    def _priority_label(score: int) -> str:
        if score >= 130:
            return "Critical"
        if score >= 90:
            return "High"
        if score >= 50:
            return "Medium"
        return "Low"

    @staticmethod
    def _impact_label(severity: str, blast_radius: str) -> str:
        if severity in {"critical", "high"} or blast_radius == "systemic":
            return "High"
        if severity == "medium" or blast_radius == "multi_file":
            return "Medium"
        return "Low"

    @staticmethod
    def _title_for_cluster(cluster: FindingCluster, severity: str) -> str:
        category, _, message_family, _ = cluster.key
        if category == "security":
            return f"Security issue pattern: {message_family[:45]}"
        if category == "complexity":
            return "Complexity hotspots in related modules"
        if category == "typing":
            return "Typing gaps reduce static safety"
        if category == "dead_code":
            return "Dead code and unused symbols"
        return f"{severity.capitalize()} {category} issue pattern"

    @staticmethod
    def _category_label(category: str) -> str:
        return category.replace("_", " ").replace("/", " / ").title()

    @staticmethod
    def _why_text(*, category: str, severity: str, blast_radius: str) -> str:
        return (
            f"{severity.capitalize()} {category.replace('_', ' ')} findings with {blast_radius.replace('_', ' ')} impact "
            "increase delivery and reliability risk."
        )

    @staticmethod
    def _recommended_fix(cluster: FindingCluster) -> str:
        category = cluster.key[0]
        if category == "security":
            return "Apply secure defaults, validate trust boundaries, and add regression tests for exploit paths."
        if category == "complexity":
            return "Split high-complexity routines, reduce branch depth, and extract cohesive helpers."
        if category == "typing":
            return "Add explicit type hints on public APIs and enable stricter type checks for affected modules."
        if category == "dead_code":
            return "Remove unused imports, symbols, and dead branches, then rerun lint checks."
        return "Standardize remediation for this rule family and enforce with CI checks."
