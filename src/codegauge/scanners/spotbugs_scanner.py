from __future__ import annotations

from typing import Sequence

from .java_build_scanner_base import JavaBuildArtifactScanner


class SpotBugsScanner(JavaBuildArtifactScanner):
    scanner_name = "spotbugs"

    @property
    def maven_tasks(self) -> Sequence[str]:
        return ("test", "verify", "spotbugs:spotbugs")

    @property
    def gradle_tasks(self) -> Sequence[str]:
        return ("test", "check", "spotbugsMain")

    @property
    def maven_artifact_paths(self) -> Sequence[str]:
        return ("target/spotbugsXml.xml",)

    @property
    def gradle_artifact_paths(self) -> Sequence[str]:
        return (
            "build/reports/spotbugs/main.xml",
            "build/reports/spotbugs/main/spotbugs.xml",
        )
