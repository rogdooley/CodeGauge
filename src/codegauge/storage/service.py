from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class PersistedScanPaths:
    project_dir: Path
    run_dir: Path
    latest_dir: Path


@dataclass(frozen=True)
class ScanDirInfo:
    project: str
    scan_dir: Path
    scan_id: str
    scan_time: datetime | None


class ScanArtifactStore:
    """Persist and query scan artifacts under report_root/projects/<project>/runs/..."""

    def __init__(self, report_root: Path) -> None:
        self.report_root = report_root

    def persist_scan_artifacts(
        self,
        *,
        project_name: str,
        summary: Mapping[str, Any],
        findings: Sequence[Mapping[str, Any]],
        score: Mapping[str, Any],
        policy: Mapping[str, Any],
        action_plan: Mapping[str, Any],
        scanner_raw_outputs: Mapping[str, Mapping[str, Any]],
    ) -> PersistedScanPaths:
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d_%H%M%S")
        project_dir = self.report_root / "projects" / project_name
        runs_root = project_dir / "runs"
        runs_root.mkdir(parents=True, exist_ok=True)
        run_dir = self._allocate_scan_dir(runs_root, timestamp)
        run_dir.mkdir(parents=True, exist_ok=False)

        report_html = run_dir / "report.html"
        self._atomic_write_json(run_dir / "summary.json", summary)
        self._atomic_write_json(run_dir / "findings.json", list(findings))
        self._atomic_write_json(run_dir / "score.json", score)
        self._atomic_write_json(run_dir / "policy.json", policy)
        self._atomic_write_json(run_dir / "action-plan.json", action_plan)
        self._atomic_write_json(run_dir / "inventory.json", dict(summary.get("inventory", {}) or {}))
        self._atomic_write_json(run_dir / "policy-resolution.json", dict(summary.get("policy_resolution", {}) or {}))

        raw_dir = run_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        for scanner_name, payload in sorted(scanner_raw_outputs.items()):
            self._atomic_write_json(raw_dir / f"{scanner_name}.json", payload)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            severity = str(finding.get("severity", "")).lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        run_manifest = {
            "project": project_name,
            "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "score": float(score.get("overall_score", 0.0) or 0.0),
            "grade": score.get("grade"),
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "report_path": str(report_html),
            "schema_version": summary.get("schema_version"),
        }
        self._atomic_write_json(run_dir / "run_manifest.json", run_manifest)

        latest_dir = project_dir / "latest"
        self._update_latest_pointer(scan_dir=run_dir, latest_dir=latest_dir)
        self._atomic_write_json(project_dir / "latest_manifest.json", run_manifest)
        return PersistedScanPaths(project_dir=project_dir, run_dir=run_dir, latest_dir=latest_dir)

    def list_scan_dirs(self, project_name: str) -> list[Path]:
        runs_root = self.report_root / "projects" / project_name / "runs"
        if not runs_root.exists():
            return []
        return sorted([path for path in runs_root.iterdir() if path.is_dir()], key=lambda item: item.name)

    def list_projects(self) -> list[str]:
        projects_root = self.report_root / "projects"
        if not projects_root.exists():
            return []
        return sorted(path.name for path in projects_root.iterdir() if path.is_dir())

    def load_json(self, path: Path) -> Any:
        return json.loads(path.read_text())

    def load_project_scan_history(self, project_name: str) -> list[dict[str, Any]]:
        history: list[dict[str, Any]] = []
        for info in self.list_scan_dir_info(project_name):
            scan_dir = info.scan_dir
            summary_path = scan_dir / "summary.json"
            score_path = scan_dir / "score.json"
            policy_path = scan_dir / "policy.json"
            run_manifest_path = scan_dir / "run_manifest.json"
            if not (summary_path.exists() and score_path.exists() and policy_path.exists()):
                continue
            summary = self.load_json(summary_path)
            score = self.load_json(score_path)
            policy = self.load_json(policy_path)
            run_manifest = self.load_json(run_manifest_path) if run_manifest_path.exists() else {}
            history.append(
                {
                    "scan_id": info.scan_id,
                    "scan_time": info.scan_time,
                    "summary": summary,
                    "score": score,
                    "policy": policy,
                    "run_manifest": run_manifest,
                    "scan_dir": scan_dir,
                }
            )
        return history

    def prune_scans_older_than(self, project_name: str, days: int, *, now: datetime | None = None, dry_run: bool = False) -> int:
        targets = self.select_scans_to_prune_days(project_name, days=days, now=now)
        if dry_run:
            return len(targets)
        for info in targets:
            shutil.rmtree(info.scan_dir)
        return len(targets)

    def select_scans_to_prune_keep(self, project_name: str, keep: int) -> list[ScanDirInfo]:
        if keep < 1:
            raise ValueError("keep must be >= 1")
        infos = self.list_scan_dir_info(project_name)
        if len(infos) <= keep:
            return []
        return infos[: len(infos) - keep]

    def select_scans_to_prune_days(
        self,
        project_name: str,
        *,
        days: int,
        now: datetime | None = None,
    ) -> list[ScanDirInfo]:
        if days < 1:
            raise ValueError("days must be >= 1")
        reference = now or datetime.now(UTC)
        cutoff = reference - timedelta(days=days)
        infos = self.list_scan_dir_info(project_name)
        latest_scan = infos[-1].scan_dir if infos else None
        selected: list[ScanDirInfo] = []
        for info in infos:
            scan_time = info.scan_time
            if scan_time is None:
                continue
            if info.scan_dir == latest_scan:
                continue
            if scan_time < cutoff:
                selected.append(info)
        return selected

    def prune_scans(self, project_name: str, keep: int) -> int:
        targets = self.select_scans_to_prune_keep(project_name, keep=keep)
        for info in targets:
            shutil.rmtree(info.scan_dir)
        return len(targets)

    def list_scan_dir_info(self, project_name: str) -> list[ScanDirInfo]:
        infos: list[ScanDirInfo] = []
        for scan_dir in self.list_scan_dirs(project_name):
            infos.append(
                ScanDirInfo(
                    project=project_name,
                    scan_dir=scan_dir,
                    scan_id=scan_dir.name,
                    scan_time=self.parse_scan_timestamp(scan_dir.name),
                )
            )
        return infos

    @staticmethod
    def parse_scan_timestamp(scan_id: str) -> datetime | None:
        try:
            date_part, _, time_part = scan_id.partition("_")
            if time_part:
                return datetime.strptime(f"{date_part}_{time_part}", "%Y-%m-%d_%H%M%S").replace(tzinfo=UTC)
        except ValueError:
            pass
        prefix = scan_id.split("_", 1)[0]
        try:
            return datetime.strptime(prefix, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
        except ValueError:
            return None

    def latest_preserved(self, project_name: str) -> bool:
        latest_path = self.report_root / "projects" / project_name / "latest"
        if not latest_path.exists() and not latest_path.is_symlink():
            return False
        try:
            if latest_path.is_symlink():
                target = latest_path.resolve()
                return target.exists()
            return latest_path.is_dir() and (latest_path / "summary.json").exists()
        except OSError:
            return False

    def _allocate_scan_dir(self, scans_root: Path, timestamp: str) -> Path:
        candidate = scans_root / timestamp
        if not candidate.exists():
            return candidate
        index = 1
        while True:
            with_suffix = scans_root / f"{timestamp}_{index:02d}"
            if not with_suffix.exists():
                return with_suffix
            index += 1

    def _update_latest_pointer(self, *, scan_dir: Path, latest_dir: Path) -> None:
        if latest_dir.exists() or latest_dir.is_symlink():
            if latest_dir.is_symlink() or latest_dir.is_file():
                latest_dir.unlink()
            else:
                shutil.rmtree(latest_dir)

        target = os.path.relpath(scan_dir, latest_dir.parent)
        try:
            latest_dir.symlink_to(target, target_is_directory=True)
            return
        except OSError:
            pass

        temp_dir = latest_dir.parent / f".latest-tmp-{scan_dir.name}"
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
        shutil.copytree(scan_dir, temp_dir)
        os.replace(temp_dir, latest_dir)

    def _atomic_write_json(self, path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_path_str = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        temp_path = Path(temp_path_str)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.replace(temp_path, path)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise
