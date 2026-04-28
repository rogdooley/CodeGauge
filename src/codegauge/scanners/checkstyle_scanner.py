from __future__ import annotations

from typing import Sequence

from .java_build_scanner_base import JavaBuildArtifactScanner


class CheckstyleScanner(JavaBuildArtifactScanner):
    scanner_name = "checkstyle"

    @property
    def maven_tasks(self) -> Sequence[str]:
        return ("test", "verify", "checkstyle:checkstyle")

    @property
    def gradle_tasks(self) -> Sequence[str]:
        return ("test", "check", "checkstyleMain")

    @property
    def maven_artifact_paths(self) -> Sequence[str]:
        return ("target/checkstyle-result.xml", "target/site/checkstyle-result.xml")

    @property
    def gradle_artifact_paths(self) -> Sequence[str]:
        return ("build/reports/checkstyle/main.xml",)
