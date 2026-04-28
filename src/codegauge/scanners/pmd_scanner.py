from __future__ import annotations

from typing import Sequence

from .java_build_scanner_base import JavaBuildArtifactScanner


class PMDScanner(JavaBuildArtifactScanner):
    scanner_name = "pmd"

    @property
    def maven_tasks(self) -> Sequence[str]:
        return ("test", "verify", "pmd:pmd")

    @property
    def gradle_tasks(self) -> Sequence[str]:
        return ("test", "check", "pmdMain")

    @property
    def maven_artifact_paths(self) -> Sequence[str]:
        return ("target/pmd.xml", "target/site/pmd.xml")

    @property
    def gradle_artifact_paths(self) -> Sequence[str]:
        return ("build/reports/pmd/main.xml",)
