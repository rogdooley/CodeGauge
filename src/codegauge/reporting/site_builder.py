from __future__ import annotations

from datetime import UTC
from pathlib import Path
from typing import Any
import re

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..storage import ScanArtifactStore


class StaticSiteBuilder:
    def __init__(self, *, report_root: Path | None = None, reports_root: Path | None = None, site_root: Path | None = None) -> None:
        if report_root is not None:
            self.artifact_root = report_root
            self.report_root = report_root
        elif reports_root is not None and site_root is not None:
            self.artifact_root = reports_root
            self.report_root = site_root
        elif reports_root is not None:
            self.artifact_root = reports_root
            self.report_root = reports_root
        elif site_root is not None:
            self.artifact_root = site_root
            self.report_root = site_root
        else:
            raise ValueError("report_root is required")
        self.store = ScanArtifactStore(self.artifact_root)
        template_dir = Path(__file__).with_name("templates")
        self.environment = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    @property
    def portal_index(self) -> Path:
        return self.report_root / "index.html"

    def build(self) -> dict[str, Any]:
        self.report_root.mkdir(parents=True, exist_ok=True)
        (self.report_root / "assets").mkdir(parents=True, exist_ok=True)
        self._write_shared_assets()
        projects = self.store.list_projects()
        project_rows: list[dict[str, Any]] = []

        for project_name in projects:
            history = self.store.load_project_scan_history(project_name)
            if not history:
                continue
            latest = history[-1]
            previous = history[-2] if len(history) > 1 else None
            latest_manifest = latest.get("run_manifest", {})
            latest_score = float(latest_manifest.get("score", latest.get("score", {}).get("overall_score", 0.0)) or 0.0)
            previous_score = (
                float(previous.get("run_manifest", {}).get("score", previous.get("score", {}).get("overall_score", 0.0)) or 0.0)
                if previous
                else None
            )
            trend_delta = round(latest_score - previous_score, 2) if previous_score is not None else None

            project_rows.append(
                {
                    "project": project_name,
                    "score": latest_score,
                    "grade": latest_manifest.get("grade", latest.get("score", {}).get("grade")),
                    "policy_status": latest.get("policy", {}).get("status", "unknown"),
                    "reason_codes": latest.get("policy", {}).get("reasons", []),
                    "critical": int(latest_manifest.get("critical", 0) or 0),
                    "high": int(latest_manifest.get("high", 0) or 0),
                    "medium": int(latest_manifest.get("medium", 0) or 0),
                    "low": int(latest_manifest.get("low", 0) or 0),
                    "trend_delta": trend_delta,
                    "language_hints": self._project_languages(latest),
                }
            )
            self._write_project_page(project_name, history)

        project_rows = self._sort_projects(project_rows)
        summary = self._build_summary(project_rows)
        self._write_index(project_rows, summary)
        return {"project_count": len(project_rows), "output_dir": str(self.report_root)}

    def _write_index(self, project_rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
        index_path = self.portal_index
        template = self.environment.get_template("index.html.j2")
        html = template.render(projects=project_rows, summary=summary, assets_prefix=self._assets_prefix(index_path))
        self._write_html(index_path, html)

    def _write_project_page(self, project_name: str, history: list[dict[str, Any]]) -> None:
        latest = history[-1]
        runs = []
        project_dir = self.report_root / "projects" / project_name
        chronological = list(history)
        previous_by_scan_id: dict[str, dict[str, Any] | None] = {}
        for idx, item in enumerate(chronological):
            previous_by_scan_id[str(item.get("scan_id"))] = chronological[idx - 1] if idx > 0 else None
        for item in reversed(chronological):
            scan_dir = Path(item["scan_dir"])
            prior = previous_by_scan_id.get(str(item.get("scan_id")))
            manifest = item.get("run_manifest", {})
            score = float(manifest.get("score", item.get("score", {}).get("overall_score", 0.0)) or 0.0)
            generated_at = str(manifest.get("generated_at") or "")
            generated_local = generated_at
            if generated_at:
                try:
                    parsed = generated_at.replace("Z", "+00:00")
                    generated_local = (
                        __import__("datetime").datetime.fromisoformat(parsed).astimezone().strftime("%Y-%m-%d %H:%M %Z")
                    )
                except ValueError:
                    generated_local = generated_at
            runs.append(
                {
                    "scan_id": item.get("scan_id"),
                    "generated_local": generated_local,
                    "generated_at": generated_at,
                    "policy_status": item.get("policy", {}).get("status", "unknown"),
                    "reason_codes": item.get("policy", {}).get("reasons", []),
                    "overall_score": score,
                    "grade": manifest.get("grade", item.get("score", {}).get("grade")),
                    "critical": int(manifest.get("critical", 0) or 0),
                    "high": int(manifest.get("high", 0) or 0),
                    "medium": int(manifest.get("medium", 0) or 0),
                    "low": int(manifest.get("low", 0) or 0),
                    "summary_link": self._relative_link(project_dir / "index.html", scan_dir / "summary.json"),
                    "findings_link": self._relative_link(project_dir / "index.html", scan_dir / "findings.json"),
                    "report_link": self._relative_link(project_dir / "index.html", scan_dir / "report.html"),
                    "details_link": self._relative_link(project_dir / "index.html", scan_dir / "details.html"),
                    "action_plan_json_link": self._relative_link(project_dir / "index.html", scan_dir / "action-plan.json"),
                    "inventory_link": self._relative_link(project_dir / "index.html", scan_dir / "inventory.json"),
                    "policy_resolution_link": self._relative_link(project_dir / "index.html", scan_dir / "policy-resolution.json"),
                }
            )
            self._write_run_pages(project_name=project_name, item=item, previous=prior)

        template = self.environment.get_template("project.html.j2")
        project_index = project_dir / "index.html"
        html = template.render(
            project=project_name,
            latest=latest,
            runs=runs,
            assets_prefix=self._assets_prefix(project_index),
        )
        self._write_html(project_index, html)

        latest_link = project_dir / "latest"
        latest_run = Path(latest["scan_dir"])
        if latest_link.exists() or latest_link.is_symlink():
            if latest_link.is_symlink() or latest_link.is_file():
                latest_link.unlink()
            else:
                import shutil

                shutil.rmtree(latest_link)
        try:
            import os

            relative = Path(os.path.relpath(latest_run, project_dir))
            latest_link.symlink_to(relative, target_is_directory=True)
        except Exception:
            import shutil

            shutil.copytree(latest_run, latest_link)

    def _write_run_pages(self, *, project_name: str, item: dict[str, Any], previous: dict[str, Any] | None) -> None:
        run_dir = Path(item["scan_dir"])
        summary = item.get("summary", {})
        score = item.get("score", {})
        action_plan = self.store.load_json(run_dir / "action-plan.json") if (run_dir / "action-plan.json").exists() else {}
        findings = self.store.load_json(run_dir / "findings.json") if (run_dir / "findings.json").exists() else []
        inventory = self.store.load_json(run_dir / "inventory.json") if (run_dir / "inventory.json").exists() else summary.get("inventory", {})
        previous_score = float((previous or {}).get("score", {}).get("overall_score", 0.0) or 0.0) if previous else None
        current_score = float(score.get("overall_score", 0.0) or 0.0)
        delta = round(current_score - previous_score, 2) if previous_score is not None else None
        generated_at = str(item.get("run_manifest", {}).get("generated_at") or "")
        generated_local = generated_at
        if generated_at:
            try:
                parsed = generated_at.replace("Z", "+00:00")
                generated_local = __import__("datetime").datetime.fromisoformat(parsed).astimezone().strftime("%Y-%m-%d %H:%M %Z")
            except ValueError:
                generated_local = generated_at

        severity_counts = self._severity_counts(findings)
        most_affected_files = self._most_affected_files(findings)
        rule_families = self._rule_family_breakdown(findings)
        finding_clusters = self._finding_clusters(findings)
        security_groups = self._security_groups(findings)
        runtime = self._runtime_metadata(summary, inventory)
        links = {
            "details": "details.html",
            "history": "../../index.html",
            "latest": "../../latest/report.html",
            "raw": "details.html#raw-artifacts",
            "summary": "summary.json",
            "findings": "findings.json",
            "action_plan": "action-plan.json",
            "inventory": "inventory.json",
            "policy_resolution": "policy-resolution.json",
            "score": "score.json",
            "policy": "policy.json",
            "manifest": "run_manifest.json",
        }

        report_template = self.environment.get_template("run_report.html.j2")
        details_template = self.environment.get_template("run_details.html.j2")
        run_report_path = run_dir / "report.html"
        run_details_path = run_dir / "details.html"
        policy_payload = item.get("policy", {})
        baseline_payload = score.get("baseline", {}) if isinstance(score.get("baseline"), dict) else {}
        security_total = sum(len(rows) for rows in security_groups.values())
        parser_global = summary.get("parser_summary", {}).get("global", {}) if isinstance(summary.get("parser_summary"), dict) else {}
        report_html = report_template.render(
            project=project_name,
            generated_at=generated_at,
            generated_local=generated_local,
            score=current_score,
            grade=score.get("grade"),
            policy_status=str(item.get("policy", {}).get("status", "unknown")).upper(),
            delta=delta,
            action_plan=action_plan,
            key_metrics=score.get("scalar_metrics", {}),
            security_count=len(action_plan.get("security_concerns", [])),
            architectural_count=len(action_plan.get("architectural_concerns", [])),
            links=links,
            assets_prefix=self._assets_prefix(run_report_path),
        )
        details_html = details_template.render(
            project=project_name,
            generated_at=generated_at,
            generated_local=generated_local,
            score=current_score,
            grade=score.get("grade"),
            policy_status=str(policy_payload.get("status", "unknown")).upper(),
            total_findings=len(findings),
            security_total=security_total,
            debt=int(baseline_payload.get("accepted_debt", 0) or 0),
            scanner_failures=int(summary.get("scanner_failures", 0) or 0),
            severity_counts=severity_counts,
            clusters=finding_clusters,
            security_groups=security_groups,
            action_plan=action_plan,
            most_affected_files=most_affected_files,
            rule_families=rule_families,
            parser_health=parser_global,
            trend={"current_score": current_score, "previous_score": previous_score, "delta": delta},
            runtime=runtime,
            links=links,
            assets_prefix=self._assets_prefix(run_details_path),
        )
        self._write_html(run_report_path, report_html)
        self._write_html(run_details_path, details_html)

    def _write_shared_assets(self) -> None:
        templates_dir = Path(__file__).with_name("templates")
        css_template = templates_dir / "assets" / "report.css"
        js_template = templates_dir / "assets" / "theme.js"
        self._write_html(self.report_root / "assets" / "report.css", css_template.read_text(encoding="utf-8"))
        self._write_html(self.report_root / "assets" / "theme.js", js_template.read_text(encoding="utf-8"))

    @staticmethod
    def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
        order = ["critical", "high", "medium", "low", "info"]
        counts = {k: 0 for k in order}
        for finding in findings:
            sev = str(finding.get("severity", "")).lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    @staticmethod
    def _most_affected_files(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        bucket: dict[str, int] = {}
        for finding in findings:
            file_path = str(finding.get("file") or "")
            if file_path:
                bucket[file_path] = bucket.get(file_path, 0) + 1
        rows = [{"file": key, "count": value} for key, value in bucket.items()]
        rows.sort(key=lambda item: (-int(item["count"]), str(item["file"])))
        return rows[:10]

    @staticmethod
    def _rule_family_breakdown(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        bucket: dict[str, int] = {}
        for finding in findings:
            rule = str(finding.get("rule_id") or "unknown").strip().lower()
            token = re.split(r"[.:/_\\-]", rule)[0] if rule else "unknown"
            bucket[token or "unknown"] = bucket.get(token or "unknown", 0) + 1
        rows = [{"rule_family": key, "count": value} for key, value in bucket.items()]
        rows.sort(key=lambda item: (-int(item["count"]), str(item["rule_family"])))
        return rows[:12]

    @staticmethod
    def _finding_clusters(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        groups: dict[tuple[str, str, str], dict[str, Any]] = {}
        for finding in findings:
            sev = str(finding.get("severity") or "info").lower()
            category = str(finding.get("category") or "unknown")
            message = str(finding.get("normalized_message") or finding.get("message") or "").strip().lower()
            key = (sev, category, " ".join(message.split(" ")[:2]) if message else "generic")
            row = groups.setdefault(
                key,
                {"severity": sev, "category": category, "message_family": key[2], "count": 0, "example_files": set()},
            )
            row["count"] += 1
            file_path = str(finding.get("file") or "")
            if file_path and len(row["example_files"]) < 3:
                row["example_files"].add(file_path)
        rows: list[dict[str, Any]] = []
        for row in groups.values():
            rows.append(
                {
                    "severity": row["severity"],
                    "category": row["category"],
                    "message_family": row["message_family"],
                    "count": row["count"],
                    "example_files": sorted(row["example_files"]),
                }
            )
        rows.sort(
            key=lambda item: (
                severity_rank.get(str(item["severity"]).lower(), 9),
                -int(item["count"]),
                str(item["category"]),
                str(item["message_family"]),
            )
        )
        return rows[:40]

    @staticmethod
    def _runtime_metadata(summary: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
        return {
            "scanner_count": int(summary.get("scanner_count", 0) or 0),
            "successful_scanners": int(summary.get("successful_scanners", 0) or 0),
            "failed_scanners": int(summary.get("failed_scanners", 0) or 0),
            "parser_summary": summary.get("parser_summary", {}),
            "inventory": inventory,
            "project_metadata": summary.get("project_metadata", {}),
        }

    @staticmethod
    def _security_groups(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        grouped = {
            "runtime": [],
            "tooling": [],
            "test_only": [],
            "false_positive": [],
        }
        for finding in findings:
            if str(finding.get("category")) != "security":
                continue
            security_class = str(finding.get("security_class") or "unknown")
            row = {
                "severity": str(finding.get("severity") or "info"),
                "rule_id": str(finding.get("rule_id") or ""),
                "file": str(finding.get("file") or ""),
                "line": finding.get("line"),
                "message": str(finding.get("message") or ""),
                "security_class": security_class,
                "score_weight": float(finding.get("score_weight", 1.0) or 1.0),
            }
            if security_class == "runtime_security":
                grouped["runtime"].append(row)
            elif security_class == "tooling_security":
                grouped["tooling"].append(row)
            elif security_class == "test_security":
                grouped["test_only"].append(row)
            elif security_class == "false_positive":
                grouped["false_positive"].append(row)
            else:
                grouped["runtime"].append(row)
        return grouped

    def _write_html(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    @staticmethod
    def _relative_link(from_file: Path, to_file: Path) -> str:
        import os

        return os.path.relpath(to_file, from_file.parent).replace(os.sep, "/")

    def _assets_prefix(self, from_file: Path) -> str:
        return self._relative_link(from_file, self.report_root / "assets")

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
    def _build_summary(project_rows: list[dict[str, Any]]) -> dict[str, Any]:
        project_count = len(project_rows)
        status_counts = {"pass": 0, "warn": 0, "fail": 0}
        for row in project_rows:
            status = str(row.get("policy_status", "")).lower()
            if status in status_counts:
                status_counts[status] += 1
        average_score = round(sum(float(row.get("score", 0.0)) for row in project_rows) / project_count, 2) if project_count else None
        language_distribution: dict[str, int] = {}
        for row in project_rows:
            for language in row.get("language_hints") or []:
                label = str(language)
                language_distribution[label] = language_distribution.get(label, 0) + 1
        return {
            "project_count": project_count,
            "pass_count": status_counts["pass"],
            "warn_count": status_counts["warn"],
            "fail_count": status_counts["fail"],
            "average_score": average_score,
            "language_distribution": dict(sorted(language_distribution.items())),
            "generated_at": __import__("datetime").datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }

    @staticmethod
    def _project_languages(item: dict[str, Any]) -> list[str]:
        summary = item.get("summary", {}) if isinstance(item.get("summary"), dict) else {}
        metadata = summary.get("project_metadata", {}) if isinstance(summary.get("project_metadata"), dict) else {}
        runtime = metadata.get("python_runtime") if isinstance(metadata.get("python_runtime"), dict) else {}
        languages: set[str] = set()
        language = runtime.get("language")
        if isinstance(language, str) and language:
            languages.add(language)
        if isinstance(metadata.get("typescript"), dict) or isinstance(metadata.get("javascript"), dict):
            if isinstance(metadata.get("typescript"), dict):
                languages.add("typescript")
            if isinstance(metadata.get("javascript"), dict):
                languages.add("javascript")
        if isinstance(metadata.get("java"), dict):
            languages.add("java")
        if isinstance(metadata.get("php"), dict):
            languages.add("php")
        if isinstance(metadata.get("go"), dict):
            languages.add("go")
        if isinstance(metadata.get("infrastructure"), dict):
            languages.add("general")
        return sorted(languages)
