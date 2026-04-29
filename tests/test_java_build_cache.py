from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from typer.testing import CliRunner

from codegauge.cli import app
from codegauge.paths import java_cache_root_for_project
from codegauge.storage import JavaBuildCacheService


runner = CliRunner()


def _seed_java_project(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "pom.xml").write_text("<project/>")
    src = root / "src" / "main" / "java" / "App.java"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("class App {}")


def test_cache_key_changes_when_source_changes(tmp_path: Path) -> None:
    _seed_java_project(tmp_path)
    service = JavaBuildCacheService(tmp_path, cache_root=java_cache_root_for_project(tmp_path / "state", tmp_path))
    module = service.discover_modules()[0]
    key_before, _ = service.compute_cache_key(module, "spotbugs")
    (tmp_path / "src" / "main" / "java" / "App.java").write_text("class App { int x = 1; }")
    key_after, _ = service.compute_cache_key(module, "spotbugs")
    assert key_before != key_after


def test_cache_key_changes_when_build_descriptor_changes(tmp_path: Path) -> None:
    _seed_java_project(tmp_path)
    service = JavaBuildCacheService(tmp_path, cache_root=java_cache_root_for_project(tmp_path / "state", tmp_path))
    module = service.discover_modules()[0]
    key_before, _ = service.compute_cache_key(module, "pmd")
    (tmp_path / "pom.xml").write_text("<project><version>2</version></project>")
    key_after, _ = service.compute_cache_key(module, "pmd")
    assert key_before != key_after


def test_multi_module_cache_is_per_module(tmp_path: Path) -> None:
    _seed_java_project(tmp_path)
    module_a = tmp_path / "module-a"
    module_b = tmp_path / "module-b"
    _seed_java_project(module_a)
    _seed_java_project(module_b)

    service = JavaBuildCacheService(tmp_path, cache_root=java_cache_root_for_project(tmp_path / "state", tmp_path))
    modules = service.discover_modules()
    assert len(modules) >= 3
    ids = {module.module_id for module in modules}
    assert len(ids) == len(modules)


def test_cache_manifest_reuse(tmp_path: Path) -> None:
    _seed_java_project(tmp_path)
    cache_root = java_cache_root_for_project(tmp_path / "state", tmp_path)
    service = JavaBuildCacheService(tmp_path, cache_root=cache_root)
    module = service.discover_modules()[0]
    key, input_hashes = service.compute_cache_key(module, "jacoco")
    artifact = tmp_path / "target" / "site" / "jacoco" / "jacoco.xml"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("<report/>")
    service.save_manifest(
        module=module,
        tool="jacoco",
        cache_key=key,
        artifact_paths=[artifact],
        input_hashes=input_hashes,
    )
    reused, reasons, _manifest = service.try_reuse(module=module, tool="jacoco", cache_key=key, input_hashes=input_hashes)
    assert reused is not None
    assert reused[0].exists()
    assert str(cache_root) in reused[0].as_posix()
    assert reasons == []


def test_cache_miss_reason_on_source_hash_change(tmp_path: Path) -> None:
    _seed_java_project(tmp_path)
    service = JavaBuildCacheService(tmp_path, cache_root=java_cache_root_for_project(tmp_path / "state", tmp_path))
    module = service.discover_modules()[0]
    key, input_hashes = service.compute_cache_key(module, "spotbugs")
    artifact = tmp_path / "target" / "spotbugsXml.xml"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("<BugCollection/>")
    service.save_manifest(
        module=module,
        tool="spotbugs",
        cache_key=key,
        artifact_paths=[artifact],
        input_hashes=input_hashes,
    )
    (tmp_path / "src" / "main" / "java" / "App.java").write_text("class App { int changed = 1; }")
    new_key, new_hashes = service.compute_cache_key(module, "spotbugs")
    reused, reasons, _ = service.try_reuse(module=module, tool="spotbugs", cache_key=new_key, input_hashes=new_hashes)
    assert reused is None
    assert "source_hash_changed" in reasons


def test_cache_history_bounded_to_last_ten(tmp_path: Path) -> None:
    _seed_java_project(tmp_path)
    service = JavaBuildCacheService(tmp_path, cache_root=java_cache_root_for_project(tmp_path / "state", tmp_path))
    module = service.discover_modules()[0]
    artifact = tmp_path / "target" / "spotbugsXml.xml"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("<BugCollection/>")
    key, input_hashes = service.compute_cache_key(module, "spotbugs")
    previous = None
    for idx in range(12):
        key_iter = f"{key}-{idx}"
        previous = service.save_manifest(
            module=module,
            tool="spotbugs",
            cache_key=key_iter,
            artifact_paths=[artifact],
            input_hashes=input_hashes,
            status="miss",
            reasons=["manifest_missing"],
            previous_cache_key=(f"{key}-{idx-1}" if idx > 0 else None),
            previous_manifest=previous,
        )
    assert previous is not None
    assert len(previous.decision_history) == 10


def test_cache_status_and_clear_cli(tmp_path: Path) -> None:
    _seed_java_project(tmp_path)
    service = JavaBuildCacheService(tmp_path, cache_root=java_cache_root_for_project(tmp_path / "state", tmp_path))
    module = service.discover_modules()[0]
    key, input_hashes = service.compute_cache_key(module, "spotbugs")
    artifact = tmp_path / "target" / "spotbugsXml.xml"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("<BugCollection/>")
    state_root = tmp_path / "state"
    (tmp_path / ".codegauge.toml").write_text(f'state_root = "{state_root.as_posix()}"\n')
    service.save_manifest(
        module=module,
        tool="spotbugs",
        cache_key=key,
        artifact_paths=[artifact],
        input_hashes=input_hashes,
    )

    status_result = runner.invoke(app, ["cache", "status", str(tmp_path), "--state-root", str(state_root)])
    assert status_result.exit_code == 0
    status = json.loads(status_result.stdout)
    assert status["modules"]
    assert "totals" in status
    assert "tools" in status["modules"][0]
    status_human = runner.invoke(app, ["cache", "status", str(tmp_path), "--state-root", str(state_root), "--human"])
    assert status_human.exit_code == 0
    assert "Cache totals:" in status_human.stdout

    status_tool = runner.invoke(app, ["cache", "status", str(tmp_path), "--state-root", str(state_root), "--tool", "spotbugs"])
    assert status_tool.exit_code == 0

    clear_dry = runner.invoke(app, ["cache", "clear", str(tmp_path), "--state-root", str(state_root), "--dry-run"])
    assert clear_dry.exit_code == 0
    payload = json.loads(clear_dry.stdout)
    assert payload["dry_run"] is True
    assert payload["removed_count"] >= 1

    clear_apply = runner.invoke(app, ["cache", "clear", str(tmp_path), "--state-root", str(state_root)])
    assert clear_apply.exit_code == 0
    payload_apply = json.loads(clear_apply.stdout)
    assert payload_apply["removed_count"] >= 1


def test_cache_clear_selective_tool_and_module(tmp_path: Path) -> None:
    _seed_java_project(tmp_path)
    service = JavaBuildCacheService(tmp_path, cache_root=java_cache_root_for_project(tmp_path / "state", tmp_path))
    module = service.discover_modules()[0]
    key, hashes = service.compute_cache_key(module, "spotbugs")
    artifact = tmp_path / "target" / "spotbugsXml.xml"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("<BugCollection/>")
    state_root = tmp_path / "state"
    (tmp_path / ".codegauge.toml").write_text(f'state_root = "{state_root.as_posix()}"\n')
    service.save_manifest(
        module=module,
        tool="spotbugs",
        cache_key=key,
        artifact_paths=[artifact],
        input_hashes=hashes,
    )
    result = runner.invoke(
        app,
        [
            "cache",
            "clear",
            str(tmp_path),
            "--state-root",
            str(state_root),
            "--module",
            module.module_name,
            "--tool",
            "spotbugs",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["removed_tool_count"] == 1


def test_cache_prune_removes_stale_manifest_and_orphan_artifact(tmp_path: Path) -> None:
    _seed_java_project(tmp_path)
    service = JavaBuildCacheService(tmp_path, cache_root=java_cache_root_for_project(tmp_path / "state", tmp_path))
    module = service.discover_modules()[0]
    key, hashes = service.compute_cache_key(module, "spotbugs")
    artifact = tmp_path / "target" / "spotbugs.xml"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("<BugCollection/>")
    manifest = service.save_manifest(
        module=module,
        tool="spotbugs",
        cache_key=key,
        artifact_paths=[artifact],
        input_hashes=hashes,
    )
    manifest_path = service.cache_root / module.module_id / "spotbugs.manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["created_at"] = (datetime.now(UTC) - timedelta(days=45)).isoformat().replace("+00:00", "Z")
    payload["decision_history"] = [
        {
            "timestamp": (datetime.now(UTC) - timedelta(days=45)).isoformat().replace("+00:00", "Z"),
            "status": "miss",
            "reasons": ["manifest_missing"],
            "previous_cache_key": None,
            "current_cache_key": manifest.cache_key,
        }
    ]
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    orphan = service.cache_root / module.module_id / "artifacts" / "spotbugs" / "orphan.xml"
    orphan.parent.mkdir(parents=True, exist_ok=True)
    orphan.write_text("<orphan/>")

    result = service.prune(days=30, max_history=10, dry_run=False)
    assert result["cache_entries_removed"] >= 1
    assert result["artifacts_removed"] >= 1
    assert not manifest_path.exists()
    assert not orphan.exists()


def test_cache_prune_cli_summary_and_dry_run(tmp_path: Path) -> None:
    _seed_java_project(tmp_path)
    service = JavaBuildCacheService(tmp_path, cache_root=java_cache_root_for_project(tmp_path / "state", tmp_path))
    module = service.discover_modules()[0]
    key, hashes = service.compute_cache_key(module, "spotbugs")
    artifact = tmp_path / "target" / "spotbugs.xml"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("<BugCollection/>")
    service.save_manifest(
        module=module,
        tool="spotbugs",
        cache_key=key,
        artifact_paths=[artifact],
        input_hashes=hashes,
    )

    result = runner.invoke(app, ["cache", "prune", str(tmp_path), "--dry-run"])
    assert result.exit_code == 0
    assert "Cache entries removed:" in result.stdout
    assert "Artifacts removed:" in result.stdout
    assert "Space reclaimed:" in result.stdout
    assert "Dry run: yes" in result.stdout


def test_cache_prune_cli_rejects_unknown_project_filter(tmp_path: Path) -> None:
    _seed_java_project(tmp_path)
    result = runner.invoke(app, ["cache", "prune", str(tmp_path), "--project", "other"])
    assert result.exit_code == 3
    assert "Project(s) not found" in result.stderr


def test_cache_prune_cli_accepts_repeatable_matching_project_filter(tmp_path: Path) -> None:
    _seed_java_project(tmp_path)
    result = runner.invoke(
        app,
        ["cache", "prune", str(tmp_path), "--project", tmp_path.name, "--project", tmp_path.name, "--dry-run"],
    )
    assert result.exit_code == 0
    assert "Dry run: yes" in result.stdout
