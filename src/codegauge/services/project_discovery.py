from __future__ import annotations

from pathlib import Path

from ..domain.models import Language, Project
from ..profiles import ProfileRegistry
from .discovery.detector_registry import DiscoveryDetectorRegistry


class ProjectDiscoveryService:
    def __init__(self, profile_registry: ProfileRegistry | None = None) -> None:
        self.profile_registry = profile_registry or ProfileRegistry.with_builtins()
        self.detectors = DiscoveryDetectorRegistry(self.profile_registry)

    def discover(self, path: Path) -> Project:
        language_hints: list[Language] = []
        metadata: dict[str, object] = {}

        if self.detectors.python.is_python_project(path):
            language_hints.append(Language.python)
        if self.detectors.java.is_java_project(path):
            language_hints.append(Language.java)
            metadata["java"] = self.detectors.java.detect(path)

        metadata.update(self.detectors.python.detect(path))

        js_meta = self.detectors.javascript.detect(path)
        if js_meta is not None:
            key = js_meta.get("key")
            js_metadata = js_meta.get("metadata")
            js_languages = js_meta.get("languages")
            if isinstance(key, str) and isinstance(js_metadata, dict):
                metadata[key] = js_metadata
            for lang in js_languages if isinstance(js_languages, list) else []:
                if isinstance(lang, Language) and lang not in language_hints:
                    language_hints.append(lang)

        infra_meta = self.detectors.infrastructure.detect(path)
        if infra_meta is not None:
            metadata["infrastructure"] = infra_meta
            if Language.general not in language_hints:
                language_hints.append(Language.general)

        return Project(name=path.name, path=path, language_hints=language_hints, metadata=metadata)
