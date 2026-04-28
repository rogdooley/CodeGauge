from __future__ import annotations

from collections import Counter
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..storage import ScanArtifactStore


class StaticSiteBuilder:
    def __init__(self, *, reports_root: Path, site_root: Path) -> None:
        self.reports_root = reports_root
        self.site_root = site_root
        self.store = ScanArtifactStore(reports_root)
        template_dir = Path(__file__).with_name("templates")
        self.environment = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def build(self) -> dict[str, Any]:
        projects = self.store.list_projects()
        project_rows: list[dict[str, Any]] = []

        projects_dir = self.site_root / "projects"
        projects_dir.mkdir(parents=True, exist_ok=True)

        for project_name in projects:
            history = self.store.load_project_scan_history(project_name)
            if not history:
                continue
            latest = history[-1]
            previous = history[-2] if len(history) > 1 else None

            latest_score = float(latest["score"].get("overall_score", 0.0))
            previous_score = float(previous["score"].get("overall_score", 0.0)) if previous else None
            trend_delta = round(latest_score - previous_score, 2) if previous_score is not None else None

            project_rows.append(
                {
                    "project": project_name,
                    "score": latest_score,
                    "grade": latest["score"].get("grade"),
                    "policy_status": latest["policy"].get("status"),
                    "reason_codes": latest["policy"].get("reasons", []),
                    "trend_delta": trend_delta,
                    "java_cache": latest["score"].get("java_cache", {}),
                    "project_metadata": latest["summary"].get("project_metadata", {}),
                }
            )

            self._write_project_page(project_name, history)

        project_rows = self._sort_projects(project_rows)
        summary_cards = self._build_summary_cards(project_rows)
        self._write_index(project_rows, summary_cards)
        return {"project_count": len(project_rows), "output_dir": str(self.site_root)}

    def _write_index(self, project_rows: list[dict[str, Any]], summary_cards: dict[str, Any]) -> None:
        template = self.environment.get_template("index.html.j2")
        html = template.render(projects=project_rows, summary=summary_cards)
        self._write_html(self.site_root / "index.html", html)

    def _write_project_page(self, project_name: str, history: list[dict[str, Any]]) -> None:
        latest = history[-1]
        findings_path = Path(latest["scan_dir"]) / "findings.json"
        findings = self.store.load_json(findings_path) if findings_path.exists() else []

        severity_counts = Counter(item.get("severity", "unknown") for item in findings)
        file_counts = Counter(item.get("file", "unknown") for item in findings)
        top_files = [{"file": file_name, "count": count} for file_name, count in file_counts.most_common(10)]

        summary = latest["summary"]
        project_metadata = summary.get("project_metadata") if isinstance(summary, dict) else {}
        java_metadata = {}
        if isinstance(project_metadata, dict):
            java_metadata = project_metadata.get("java") if isinstance(project_metadata.get("java"), dict) else {}
        dedupe = latest["score"].get("dedupe", {}) if isinstance(latest.get("score"), dict) else {}
        baseline = latest["score"].get("baseline", {}) if isinstance(latest.get("score"), dict) else {}
        java_cache = latest["score"].get("java_cache", {}) if isinstance(latest.get("score"), dict) else {}
        scanner_suppressed = dedupe.get("suppressed_per_scanner", {}) if isinstance(dedupe, dict) else {}
        scanner_status = [
            {
                "scanner_name": entry.get("scanner_name"),
                "success": entry.get("success"),
                "error_code": entry.get("error_code"),
                "finding_count": entry.get("finding_count"),
                "duration_ms": entry.get("duration_ms"),
                "duplicates_suppressed": int(scanner_suppressed.get(entry.get("scanner_name"), 0)),
            }
            for entry in summary.get("results", [])
        ]

        runs = []
        for item in reversed(history):
            scan_dir = Path(item["scan_dir"])
            scan_id = str(item.get("scan_id"))
            scan_time = item.get("scan_time")
            runs.append(
                {
                    "scan_id": scan_id,
                    "local_timestamp": self._format_scan_time_local(scan_time, fallback=scan_id),
                    "utc_timestamp": self._format_scan_time_utc(scan_time, fallback=scan_id),
                    "policy_status": item.get("policy", {}).get("status", "unknown"),
                    "reason_codes": item.get("policy", {}).get("reasons", []),
                    "overall_score": float(item.get("score", {}).get("overall_score", 0.0)),
                    "grade": item.get("score", {}).get("grade"),
                    "summary_link": self._artifact_link(scan_dir, "summary.json"),
                    "findings_link": self._artifact_link(scan_dir, "findings.json"),
                    "score_link": self._artifact_link(scan_dir, "score.json"),
                    "policy_link": self._artifact_link(scan_dir, "policy.json"),
                    "raw_link": self._artifact_link(scan_dir, "raw"),
                }
            )

        trend = [
            {
                "scan_id": item.get("scan_id"),
                "overall_score": item.get("score", {}).get("overall_score"),
                "grade": item.get("score", {}).get("grade"),
                "policy_status": item.get("policy", {}).get("status"),
                "maintainability_index": item.get("score", {}).get("scalar_metrics", {}).get("maintainability_index"),
                "average_complexity": item.get("score", {}).get("scalar_metrics", {}).get("average_complexity"),
                "worst_complexity": item.get("score", {}).get("scalar_metrics", {}).get("worst_complexity"),
                "accepted_debt": item.get("score", {}).get("baseline", {}).get("accepted_debt"),
                "new_debt": item.get("score", {}).get("baseline", {}).get("new_findings"),
                "resolved_debt": item.get("score", {}).get("baseline", {}).get("resolved_findings"),
            }
            for item in history
        ]
        java_trend = [
            {
                "scan_id": item.get("scan_id"),
                "coverage_percent": item.get("score", {}).get("scalar_metrics", {}).get("coverage_percent"),
                "branch_coverage_percent": item.get("score", {}).get("scalar_metrics", {}).get("branch_coverage_percent"),
                "duplication_percent": item.get("score", {}).get("scalar_metrics", {}).get("duplication_percent"),
                "maintainability_grade": item.get("score", {}).get("scalar_metrics", {}).get("maintainability_grade"),
            }
            for item in history
        ]
        show_java_trend = any(
            row["coverage_percent"] is not None
            or row["branch_coverage_percent"] is not None
            or row["duplication_percent"] is not None
            or row["maintainability_grade"] is not None
            for row in java_trend
        )

        template = self.environment.get_template("project.html.j2")
        html = template.render(
            project=project_name,
            summary=summary,
            score=latest["score"],
            policy=latest["policy"],
            project_metadata=project_metadata or {},
            java_metadata=java_metadata or {},
            dedupe=dedupe,
            baseline=baseline,
            java_cache=java_cache,
            framework_cards=self._build_framework_cards(project_metadata or {}),
            baseline_governance=self._build_baseline_governance(baseline),
            metric_cards=self._build_metric_cards(latest["score"], latest["policy"]),
            java_metric_cards=self._build_java_metric_cards(latest["score"]),
            spring_posture_cards=self._build_spring_posture_cards(findings),
            severity_counts=dict(sorted(severity_counts.items())),
            top_files=top_files,
            scanner_status=scanner_status,
            trend=trend,
            java_trend=java_trend,
            show_java_trend=show_java_trend,
            runs=runs,
        )
        self._write_html(self.site_root / "projects" / f"{project_name}.html", html)

    def _write_html(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _artifact_link(self, scan_dir: Path, artifact: str) -> str:
        page_root = self.site_root / "projects"
        target = scan_dir / artifact
        return os.path.relpath(target, page_root).replace(os.sep, "/")

    @staticmethod
    def _format_scan_time_local(scan_time: datetime | None, *, fallback: str) -> str:
        if scan_time is None:
            return fallback
        localized = scan_time.astimezone()
        return localized.strftime("%Y-%m-%d %H:%M %Z")

    @staticmethod
    def _format_scan_time_utc(scan_time: datetime | None, *, fallback: str) -> str:
        if scan_time is None:
            return fallback
        normalized = scan_time.astimezone(UTC)
        return normalized.strftime("%Y-%m-%d %H:%M UTC")

    @staticmethod
    def _sort_projects(project_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        policy_rank = {"fail": 0, "warn": 1, "pass": 2}
        return sorted(
            project_rows,
            key=lambda row: (
                policy_rank.get(str(row.get("policy_status", "")).lower(), 3),
                float(row.get("score", 0.0)),
                str(row.get("project", "")),
            ),
        )

    @staticmethod
    def _build_summary_cards(project_rows: list[dict[str, Any]]) -> dict[str, Any]:
        project_count = len(project_rows)
        status_counts = {"pass": 0, "warn": 0, "fail": 0}
        scores = []
        for row in project_rows:
            status = str(row.get("policy_status", "")).lower()
            if status in status_counts:
                status_counts[status] += 1
            scores.append(float(row.get("score", 0.0)))

        average_score = round(sum(scores) / len(scores), 2) if scores else None
        worst_project = project_rows[0] if project_rows else None
        improvement_candidates = [row for row in project_rows if row.get("trend_delta") is not None]
        most_improved = None
        if improvement_candidates:
            most_improved = max(improvement_candidates, key=lambda row: float(row["trend_delta"]))

        language_cache_efficiency = StaticSiteBuilder._build_language_cache_efficiency(project_rows)
        return {
            "project_count": project_count,
            "pass_count": status_counts["pass"],
            "warn_count": status_counts["warn"],
            "fail_count": status_counts["fail"],
            "average_score": average_score,
            "worst_project": worst_project,
            "most_improved_project": most_improved,
            "cache_hits": sum(int((row.get("java_cache") or {}).get("cache_hits", 0) or 0) for row in project_rows),
            "cache_misses": sum(int((row.get("java_cache") or {}).get("cache_misses", 0) or 0) for row in project_rows),
            "cache_hit_rate": (
                round(
                    (
                        sum(int((row.get("java_cache") or {}).get("cache_hits", 0) or 0) for row in project_rows)
                        / (
                            sum(int((row.get("java_cache") or {}).get("cache_hits", 0) or 0) for row in project_rows)
                            + sum(int((row.get("java_cache") or {}).get("cache_misses", 0) or 0) for row in project_rows)
                        )
                    )
                    * 100.0,
                    2,
                )
                if (
                    sum(int((row.get("java_cache") or {}).get("cache_hits", 0) or 0) for row in project_rows)
                    + sum(int((row.get("java_cache") or {}).get("cache_misses", 0) or 0) for row in project_rows)
                )
                > 0
                else None
            ),
            "language_cache_efficiency": language_cache_efficiency,
        }

    @staticmethod
    def _build_language_cache_efficiency(project_rows: list[dict[str, Any]]) -> dict[str, float | None]:
        buckets = {
            "python": {"hits": 0, "misses": 0},
            "java": {"hits": 0, "misses": 0},
            "javascript": {"hits": 0, "misses": 0},
            "django": {"hits": 0, "misses": 0},
        }
        for row in project_rows:
            metadata = row.get("project_metadata")
            if not isinstance(metadata, dict):
                continue
            java_cache = row.get("java_cache")
            if not isinstance(java_cache, dict):
                continue
            hits = int(java_cache.get("cache_hits", 0) or 0)
            misses = int(java_cache.get("cache_misses", 0) or 0)
            if "java" in metadata:
                buckets["java"]["hits"] += hits
                buckets["java"]["misses"] += misses
            if "python" in metadata:
                buckets["python"]["hits"] += hits
                buckets["python"]["misses"] += misses
            if "javascript" in metadata or "typescript" in metadata:
                buckets["javascript"]["hits"] += hits
                buckets["javascript"]["misses"] += misses
            if "django" in metadata:
                buckets["django"]["hits"] += hits
                buckets["django"]["misses"] += misses
        efficiency: dict[str, float | None] = {}
        for key, counts in buckets.items():
            total = counts["hits"] + counts["misses"]
            efficiency[key] = round((counts["hits"] / total) * 100.0, 2) if total > 0 else None
        return efficiency

    @staticmethod
    def _build_metric_cards(score: dict[str, Any], policy: dict[str, Any]) -> list[dict[str, str]]:
        _ = policy
        category_scores = {
            entry.get("category"): float(entry.get("score", 0.0))
            for entry in score.get("category_scores", [])
            if isinstance(entry, dict)
        }
        finding_counts = score.get("finding_counts", {})
        scalar_metrics = score.get("scalar_metrics", {})
        measured_categories = set(score.get("measured_categories", []))

        coverage = scalar_metrics.get("coverage_percent")
        maintainability_grade = scalar_metrics.get("maintainability_grade")
        maintainability_index = scalar_metrics.get("maintainability_index")
        complexity_grade = scalar_metrics.get("complexity_grade")

        dead_code_value = "n/a"
        if "dead_code" in measured_categories:
            dead_code_count = int(finding_counts.get("dead_code", 0))
            dead_code_value = f"{dead_code_count} findings"

        if maintainability_grade is None and isinstance(maintainability_index, (int, float)):
            maintainability_grade = StaticSiteBuilder._grade_for_score(float(maintainability_index))

        cards = [
            {
                "label": "Coverage",
                "value": f"{float(coverage):.0f}%" if isinstance(coverage, (int, float)) else "n/a",
            },
            {
                "label": "Maintainability",
                "value": str(maintainability_grade) if maintainability_grade is not None else "n/a",
            },
            {"label": "Complexity", "value": str(complexity_grade) if complexity_grade is not None else "n/a"},
            {"label": "Dead code", "value": dead_code_value},
        ]
        project_meta = score.get("project_metadata") if isinstance(score.get("project_metadata"), dict) else {}
        _ = project_meta
        return cards

    @staticmethod
    def _build_framework_cards(project_metadata: dict[str, Any]) -> list[dict[str, str]]:
        cards: list[dict[str, str]] = []
        django = project_metadata.get("django") if isinstance(project_metadata.get("django"), dict) else {}
        javascript = project_metadata.get("javascript") if isinstance(project_metadata.get("javascript"), dict) else {}
        typescript = project_metadata.get("typescript") if isinstance(project_metadata.get("typescript"), dict) else {}
        infrastructure = (
            project_metadata.get("infrastructure") if isinstance(project_metadata.get("infrastructure"), dict) else {}
        )

        if django:
            cards.append({"label": "Django", "value": "detected"})
            cards.append({"label": "DRF", "value": "yes" if django.get("drf") else "no"})
            cards.append({"label": "Channels", "value": "yes" if django.get("channels") else "no"})
            cards.append({"label": "Templates", "value": str(int(django.get("template_count", 0)))})

        js_meta = typescript or javascript
        if js_meta:
            frameworks = js_meta.get("frameworks") if isinstance(js_meta.get("frameworks"), list) else []
            cards.append({"label": "JS/TS Frameworks", "value": ", ".join(frameworks) if frameworks else "n/a"})
            cards.append({"label": "Package manager", "value": str(js_meta.get("package_manager") or "unknown")})
            cards.append({"label": "Dependency count", "value": str(int(js_meta.get("dependency_count", 0)))})

        if infrastructure:
            cards.extend(StaticSiteBuilder._build_infrastructure_cards(infrastructure))

        return cards

    @staticmethod
    def _build_infrastructure_cards(infrastructure: dict[str, Any]) -> list[dict[str, str]]:
        def _count(key: str) -> int:
            value = infrastructure.get(key)
            if isinstance(value, list):
                return len(value)
            return 0

        container_count = _count("dockerfiles")
        proxy_count = _count("traefik_configs") + _count("apache_configs") + _count("nginx_configs")
        exposure_count = _count("compose_files") + _count("quadlets")
        terraform_count = _count("terraform_files")
        shell_count = _count("shell_scripts")

        def _status_from_count(count: int, *, risk_when_present: bool = False) -> str:
            if count == 0:
                return "n/a"
            if risk_when_present:
                return "review"
            return "observed"

        return [
            {"label": "Container Hardening", "value": _status_from_count(container_count, risk_when_present=True)},
            {"label": "Reverse Proxy Posture", "value": _status_from_count(proxy_count, risk_when_present=True)},
            {"label": "Infrastructure Exposure", "value": _status_from_count(exposure_count, risk_when_present=True)},
            {"label": "Secrets Hygiene", "value": _status_from_count(container_count + terraform_count + shell_count, risk_when_present=True)},
            {"label": "Runtime Isolation", "value": _status_from_count(container_count + exposure_count, risk_when_present=True)},
            {"label": "IaC Safety", "value": _status_from_count(terraform_count, risk_when_present=True)},
            {"label": "Shell Hygiene", "value": _status_from_count(shell_count, risk_when_present=True)},
        ]

    @staticmethod
    def _build_baseline_governance(baseline: dict[str, Any]) -> list[dict[str, str]]:
        def _value(key: str) -> str:
            value = baseline.get(key)
            if isinstance(value, int):
                return str(value)
            return "n/a"

        return [
            {"label": "Accepted Entries", "value": _value("accepted_entries")},
            {"label": "Expired Entries", "value": _value("expired_entries")},
            {"label": "Expiring Soon", "value": _value("expiring_soon_entries")},
            {"label": "Missing Owner", "value": _value("missing_owner_entries")},
        ]

    @staticmethod
    def _build_java_metric_cards(score: dict[str, Any]) -> list[dict[str, str]]:
        scalar_metrics = score.get("scalar_metrics", {})
        cards: list[dict[str, str]] = []
        cards.append(
            {
                "label": "Branch Coverage",
                "value": (
                    f"{float(scalar_metrics['branch_coverage_percent']):.0f}%"
                    if isinstance(scalar_metrics.get("branch_coverage_percent"), (int, float))
                    else "n/a"
                ),
            }
        )
        cards.append(
            {
                "label": "Duplication",
                "value": (
                    f"{float(scalar_metrics['duplication_percent']):.1f}%"
                    if isinstance(scalar_metrics.get("duplication_percent"), (int, float))
                    else "n/a"
                ),
            }
        )
        cards.append(
            {
                "label": "Avg Complexity",
                "value": (
                    f"{float(scalar_metrics['avg_complexity']):.2f}"
                    if isinstance(scalar_metrics.get("avg_complexity"), (int, float))
                    else "n/a"
                ),
            }
        )
        cards.append(
            {
                "label": "Worst Complexity",
                "value": (
                    f"{float(scalar_metrics['worst_complexity']):.2f}"
                    if isinstance(scalar_metrics.get("worst_complexity"), (int, float))
                    else "n/a"
                ),
            }
        )
        cards.append(
            {
                "label": "Class Count",
                "value": (
                    str(int(scalar_metrics["class_count"]))
                    if isinstance(scalar_metrics.get("class_count"), (int, float))
                    else "n/a"
                ),
            }
        )
        cards.append(
            {
                "label": "Method Count",
                "value": (
                    str(int(scalar_metrics["method_count"]))
                    if isinstance(scalar_metrics.get("method_count"), (int, float))
                    else "n/a"
                ),
            }
        )
        return cards

    @staticmethod
    def _build_spring_posture_cards(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
        posture_keys = (
            "security_posture",
            "validation_hygiene",
            "persistence_safety",
            "api_contract_hygiene",
            "actuator_exposure",
        )
        counts = {key: 0 for key in posture_keys}
        for finding in findings:
            payload = finding.get("raw_payload")
            if isinstance(payload, dict):
                posture = payload.get("spring_posture")
                if isinstance(posture, str) and posture in counts:
                    counts[posture] += 1
        cards: list[dict[str, str]] = []
        for key in posture_keys:
            label = key.replace("_", " ").title()
            value = "PASS" if counts[key] == 0 else f"{counts[key]} issues"
            cards.append({"label": label, "value": value})
        return cards

    @staticmethod
    def _grade_for_score(score: float) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"
