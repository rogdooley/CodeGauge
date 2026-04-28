from __future__ import annotations

from typing import Sequence

from .java_build_scanner_base import JavaBuildArtifactScanner


class JaCoCoScanner(JavaBuildArtifactScanner):
    scanner_name = "jacoco"

    @property
    def maven_tasks(self) -> Sequence[str]:
        return ("test", "verify")

    @property
    def gradle_tasks(self) -> Sequence[str]:
        return ("test", "check", "jacocoTestReport")

    @property
    def maven_artifact_paths(self) -> Sequence[str]:
        return ("target/site/jacoco/jacoco.xml",)

    @property
    def gradle_artifact_paths(self) -> Sequence[str]:
        return ("build/reports/jacoco/test/jacocoTestReport.xml",)
