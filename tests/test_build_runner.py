from __future__ import annotations

from pathlib import Path

from codegauge.services.build_runner import BuildRunner, GradleRunner, MavenRunner, select_build_runner
from codegauge.scanners import (
    CheckstyleScanner,
    DependencyCheckScanner,
    ErrorProneScanner,
    JaCoCoScanner,
    PMDScanner,
    SpotBugsScanner,
)
from codegauge.scanners.java_build_scanner_base import JavaBuildArtifactScanner


class _TestScanner(JavaBuildArtifactScanner):
    scanner_name = "test_java_scanner"

    @property
    def maven_tasks(self):
        return ("verify",)

    @property
    def gradle_tasks(self):
        return ("check",)

    @property
    def maven_artifact_paths(self):
        return ("target/test-report.xml",)

    @property
    def gradle_artifact_paths(self):
        return ("build/reports/test-report.xml",)


def test_select_build_runner_prefers_maven_when_pom_present(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project/>")
    runner = select_build_runner(tmp_path)
    assert isinstance(runner, MavenRunner)


def test_select_build_runner_uses_gradle_when_gradle_files_present(tmp_path: Path) -> None:
    (tmp_path / "build.gradle").write_text("plugins {}")
    runner = select_build_runner(tmp_path)
    assert isinstance(runner, GradleRunner)


def test_maven_runner_uses_wrapper_when_present(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project/>")
    (tmp_path / "mvnw").write_text("#!/bin/sh")
    runner = MavenRunner()
    plan = runner.build_plan(
        tmp_path,
        tasks=("test", "verify"),
        artifact_relative_paths=("target/site/jacoco/jacoco.xml",),
        extra_args=(),
    )
    assert plan.command[:3] == ["./mvnw", "test", "verify"]
    assert str(plan.artifact_candidates[0]).endswith("target/site/jacoco/jacoco.xml")


def test_gradle_runner_uses_wrapper_when_present(tmp_path: Path) -> None:
    (tmp_path / "build.gradle.kts").write_text("plugins {}")
    (tmp_path / "gradlew").write_text("#!/bin/sh")
    runner = GradleRunner()
    plan = runner.build_plan(
        tmp_path,
        tasks=("test", "check", "jacocoTestReport"),
        artifact_relative_paths=("build/reports/jacoco/test/jacocoTestReport.xml",),
        extra_args=(),
    )
    assert plan.command[:4] == ["./gradlew", "test", "check", "jacocoTestReport"]
    assert str(plan.artifact_candidates[0]).endswith("build/reports/jacoco/test/jacocoTestReport.xml")


def test_build_runner_resolve_first_existing(tmp_path: Path) -> None:
    candidate_one = tmp_path / "a" / "missing.xml"
    candidate_two = tmp_path / "b" / "exists.xml"
    candidate_two.parent.mkdir(parents=True, exist_ok=True)
    candidate_two.write_text("<xml/>")
    resolved = BuildRunner.resolve_first_existing(tmp_path, [candidate_one, candidate_two])
    assert resolved == candidate_two


def test_java_scanners_emit_maven_or_gradle_commands(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project/>")
    assert SpotBugsScanner().build_command(tmp_path)[:3] == ["mvn", "test", "verify"]
    assert PMDScanner().build_command(tmp_path)[:3] == ["mvn", "test", "verify"]
    assert CheckstyleScanner().build_command(tmp_path)[:3] == ["mvn", "test", "verify"]
    assert ErrorProneScanner().build_command(tmp_path)[:3] == ["mvn", "test", "verify"]
    assert JaCoCoScanner().build_command(tmp_path)[:3] == ["mvn", "test", "verify"]
    assert DependencyCheckScanner().build_command(tmp_path)[:3] == ["mvn", "test", "verify"]


def test_java_scanner_reuses_cached_artifact(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "pom.xml").write_text("<project/>")
    calls: list[int] = []

    class _Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def _fake_run(*args, **kwargs):
        calls.append(1)
        artifact = tmp_path / "target" / "test-report.xml"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("<report><file/></report>")
        return _Completed()

    monkeypatch.setattr("codegauge.scanners.java_build_scanner_base.subprocess.run", _fake_run)

    scanner = _TestScanner()
    first = scanner.execute(tmp_path)
    assert first.success is True
    assert len(calls) == 1
    assert first.metadata is not None
    cache_meta = first.metadata["cache"]
    assert cache_meta["cache_misses"] == 1
    assert cache_meta["miss_reason_counts"]["manifest_missing"] == 1

    second = scanner.execute(tmp_path)
    assert second.success is True
    assert len(calls) == 1
    assert second.metadata is not None
    cache_meta_second = second.metadata["cache"]
    assert cache_meta_second["cache_hits"] == 1
