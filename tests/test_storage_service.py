from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from codegauge.storage import ScanArtifactStore


def _sample_payload(project: str) -> tuple[dict, list[dict], dict, dict, dict]:
    summary = {
        "project": project,
        "schema_version": "2.0.0",
        "scanner_count": 1,
        "successful_scanners": 1,
        "failed_scanners": 0,
        "finding_count": 1,
        "invalid_findings": 0,
        "invalid_paths": 0,
        "parse_failures": 0,
        "parser_missing": 0,
        "scanner_failures": 0,
        "duration_ms": 12.4,
        "results": [{"scanner_name": "ruff", "success": True, "error_code": None, "finding_count": 1, "duration_ms": 12.4}],
    }
    findings = [{"tool": "ruff", "rule_id": "F401", "severity": "low", "category": "dead_code", "file": "src/a.py"}]
    score = {"overall_score": 91.0, "grade": "A", "category_scores": [], "finding_counts": {}, "warnings": []}
    policy = {"status": "pass", "reasons": [], "violations": [], "warnings": [], "summary": "ok"}
    raw = {"ruff": {"command": ["ruff", "check", "."], "stdout": "[]", "stderr": "", "exit_code": 0, "error_code": None}}
    return summary, findings, score, policy, raw


def test_persist_scan_artifacts_portal_layout_and_latest_pointer(tmp_path: Path) -> None:
    store = ScanArtifactStore(tmp_path / "portal")
    summary, findings, score, policy, raw = _sample_payload("demo")

    persisted = store.persist_scan_artifacts(
        project_name="demo",
        summary=summary,
        findings=findings,
        score=score,
        policy=policy,
        action_plan={"schema_version": "1.0.0", "executive_summary": "ok"},
        scanner_raw_outputs=raw,
    )

    assert persisted.run_dir.exists()
    assert (persisted.run_dir / "summary.json").exists()
    assert (persisted.run_dir / "findings.json").exists()
    assert (persisted.run_dir / "score.json").exists()
    assert (persisted.run_dir / "policy.json").exists()
    assert (persisted.run_dir / "run_manifest.json").exists()
    assert (persisted.run_dir / "action-plan.json").exists()
    assert (persisted.run_dir / "inventory.json").exists()
    assert (persisted.run_dir / "policy-resolution.json").exists()
    assert (persisted.run_dir / "raw" / "ruff.json").exists()

    manifest = json.loads((persisted.run_dir / "run_manifest.json").read_text())
    assert manifest["project"] == "demo"
    assert manifest["score"] == 91.0
    assert manifest["grade"] == "A"
    assert manifest["low"] == 1
    assert manifest["high"] == 0

    latest = persisted.latest_dir
    assert latest.exists()
    assert (latest / "summary.json").exists()
    assert (persisted.project_dir / "latest_manifest.json").exists()


def test_list_and_prune_run_dirs(tmp_path: Path) -> None:
    store = ScanArtifactStore(tmp_path / "portal")
    summary, findings, score, policy, raw = _sample_payload("demo")

    store.persist_scan_artifacts(
        project_name="demo",
        summary=summary,
        findings=findings,
        score=score,
        policy=policy,
        action_plan={"schema_version": "1.0.0", "executive_summary": "ok"},
        scanner_raw_outputs=raw,
    )
    store.persist_scan_artifacts(
        project_name="demo",
        summary=summary,
        findings=findings,
        score=score,
        policy=policy,
        action_plan={"schema_version": "1.0.0", "executive_summary": "ok"},
        scanner_raw_outputs=raw,
    )

    run_dirs = store.list_scan_dirs("demo")
    assert len(run_dirs) == 2

    removed = store.prune_scans("demo", keep=1)
    assert removed == 1
    assert len(store.list_scan_dirs("demo")) == 1


def test_prune_runs_older_than(tmp_path: Path) -> None:
    store = ScanArtifactStore(tmp_path / "portal")
    summary, findings, score, policy, raw = _sample_payload("demo")
    old_run = store.persist_scan_artifacts(
        project_name="demo",
        summary=summary,
        findings=findings,
        score=score,
        policy=policy,
        action_plan={"schema_version": "1.0.0", "executive_summary": "ok"},
        scanner_raw_outputs=raw,
    )
    new_run = store.persist_scan_artifacts(
        project_name="demo",
        summary=summary,
        findings=findings,
        score=score,
        policy=policy,
        action_plan={"schema_version": "1.0.0", "executive_summary": "ok"},
        scanner_raw_outputs=raw,
    )

    renamed_old = old_run.run_dir.parent / "2020-01-01_000000"
    old_run.run_dir.rename(renamed_old)
    renamed_new = new_run.run_dir.parent / "2099-01-01_000000"
    new_run.run_dir.rename(renamed_new)

    removed_dry_run = store.prune_scans_older_than("demo", days=30, now=datetime(2026, 1, 1, tzinfo=UTC), dry_run=True)
    assert removed_dry_run == 1
    assert len(store.list_scan_dirs("demo")) == 2

    removed = store.prune_scans_older_than("demo", days=30, now=datetime(2026, 1, 1, tzinfo=UTC), dry_run=False)
    assert removed == 1
    run_names = [path.name for path in store.list_scan_dirs("demo")]
    assert "2099-01-01_000000" in run_names
    assert "2020-01-01_000000" not in run_names
