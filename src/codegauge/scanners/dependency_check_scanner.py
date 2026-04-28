from __future__ import annotations

from typing import Sequence

from .java_build_scanner_base import JavaBuildArtifactScanner


class DependencyCheckScanner(JavaBuildArtifactScanner):
    scanner_name = "dependency_check"

    @property
    def maven_tasks(self) -> Sequence[str]:
        return ("test", "verify", "dependency-check:check")

    @property
    def gradle_tasks(self) -> Sequence[str]:
        return ("test", "check", "dependencyCheckAnalyze")

    @property
    def maven_artifact_paths(self) -> Sequence[str]:
        return ("target/dependency-check-report.json",)

    @property
    def gradle_artifact_paths(self) -> Sequence[str]:
        return ("build/reports/dependency-check-report.json",)
