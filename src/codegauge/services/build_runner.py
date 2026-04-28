from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class BuildExecutionPlan:
    command: list[str]
    artifact_candidates: list[Path]
    runner_name: str


class BuildRunner(ABC):
    runner_name: str

    @abstractmethod
    def supports(self, project_path: Path) -> bool:
        ...

    @abstractmethod
    def is_available(self, project_path: Path) -> bool:
        ...

    @abstractmethod
    def build_plan(
        self,
        project_path: Path,
        *,
        tasks: Sequence[str],
        artifact_relative_paths: Sequence[str],
        extra_args: Sequence[str],
    ) -> BuildExecutionPlan:
        ...

    @staticmethod
    def resolve_first_existing(
        project_path: Path,
        artifact_candidates: Sequence[Path],
    ) -> Path | None:
        for candidate in artifact_candidates:
            absolute = candidate if candidate.is_absolute() else project_path / candidate
            if absolute.exists() and absolute.is_file():
                return absolute
        return None


class MavenRunner(BuildRunner):
    runner_name = "maven"

    def supports(self, project_path: Path) -> bool:
        return (project_path / "pom.xml").exists() or (project_path / "mvnw").exists()

    def is_available(self, project_path: Path) -> bool:
        if (project_path / "mvnw").exists():
            return True
        return shutil.which("mvn") is not None

    def build_plan(
        self,
        project_path: Path,
        *,
        tasks: Sequence[str],
        artifact_relative_paths: Sequence[str],
        extra_args: Sequence[str],
    ) -> BuildExecutionPlan:
        executable = "./mvnw" if (project_path / "mvnw").exists() else "mvn"
        command = [executable, *tasks, *extra_args]
        candidates = [project_path / relative for relative in artifact_relative_paths]
        return BuildExecutionPlan(command=command, artifact_candidates=candidates, runner_name=self.runner_name)


class GradleRunner(BuildRunner):
    runner_name = "gradle"

    def supports(self, project_path: Path) -> bool:
        return any(
            (project_path / marker).exists()
            for marker in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradlew")
        )

    def is_available(self, project_path: Path) -> bool:
        if (project_path / "gradlew").exists():
            return True
        return shutil.which("gradle") is not None

    def build_plan(
        self,
        project_path: Path,
        *,
        tasks: Sequence[str],
        artifact_relative_paths: Sequence[str],
        extra_args: Sequence[str],
    ) -> BuildExecutionPlan:
        executable = "./gradlew" if (project_path / "gradlew").exists() else "gradle"
        command = [executable, *tasks, *extra_args]
        candidates = [project_path / relative for relative in artifact_relative_paths]
        return BuildExecutionPlan(command=command, artifact_candidates=candidates, runner_name=self.runner_name)


def select_build_runner(project_path: Path) -> BuildRunner | None:
    runners: list[BuildRunner] = [MavenRunner(), GradleRunner()]
    for runner in runners:
        if runner.supports(project_path):
            return runner
    return None

