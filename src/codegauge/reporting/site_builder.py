from __future__ import annotations

from datetime import UTC
from pathlib import Path
from typing import Any

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
                }
            )
            self._write_project_page(project_name, history)

        project_rows = self._sort_projects(project_rows)
        summary = self._build_summary(project_rows)
        self._write_index(project_rows, summary)
        return {"project_count": len(project_rows), "output_dir": str(self.report_root)}

    def _write_index(self, project_rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
        template = self.environment.get_template("index.html.j2")
        html = template.render(projects=project_rows, summary=summary)
        self._write_html(self.portal_index, html)

    def _write_project_page(self, project_name: str, history: list[dict[str, Any]]) -> None:
        latest = history[-1]
        runs = []
        project_dir = self.report_root / "projects" / project_name
        for item in reversed(history):
            scan_dir = Path(item["scan_dir"])
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
                }
            )

        template = self.environment.get_template("project.html.j2")
        html = template.render(
            project=project_name,
            latest=latest,
            runs=runs,
        )
        self._write_html(project_dir / "index.html", html)

        latest_link = project_dir / "latest"
        latest_run = Path(latest["scan_dir"])
        latest_report_target = project_dir / "latest" / "report.html"
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

        runs = list(reversed(runs))
        report_template = self.environment.get_template("project.html.j2")
        for run in runs:
            run_dir = project_dir / "runs" / str(run["scan_id"])
            run_dir.mkdir(parents=True, exist_ok=True)
            run_html = report_template.render(
                project=project_name,
                latest=latest,
                runs=[run],
            )
            self._write_html(run_dir / "report.html", run_html)

    def _write_html(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    @staticmethod
    def _relative_link(from_file: Path, to_file: Path) -> str:
        import os

        return os.path.relpath(to_file, from_file.parent).replace(os.sep, "/")

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
        return {
            "project_count": project_count,
            "pass_count": status_counts["pass"],
            "warn_count": status_counts["warn"],
            "fail_count": status_counts["fail"],
            "average_score": average_score,
            "generated_at": __import__("datetime").datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
