from __future__ import annotations

import re
from pathlib import Path

from ...profiles import JavaFramework, JavaFrameworkProfile, JavaProfile, ProfileRegistry
from .base import DiscoveryHelper

_JAVA_BUILD_MARKERS = (
    "pom.xml",
    "mvnw",
    "build.gradle",
    "build.gradle.kts",
    "gradlew",
    "settings.gradle",
    "settings.gradle.kts",
)

_SPRING_COORDINATE_RE = re.compile(r"org\.springframework(?:\.boot)?", re.IGNORECASE)
_MICRONAUT_COORDINATE_RE = re.compile(r"io\.micronaut", re.IGNORECASE)
_QUARKUS_COORDINATE_RE = re.compile(r"io\.quarkus", re.IGNORECASE)
_JAKARTA_COORDINATE_RE = re.compile(r"jakarta\.[a-z0-9_.-]+", re.IGNORECASE)

_SPRING_ANNOTATION_PATTERNS: dict[str, re.Pattern[str]] = {
    "spring_component_annotations": re.compile(r"@(?:RestController|Controller|Service|Component|Repository)\b"),
    "spring_security_annotations": re.compile(r"@(?:PreAuthorize|Secured|RolesAllowed)\b"),
    "spring_validation_annotations": re.compile(r"@(?:Valid|Validated)\b"),
    "spring_jpa_annotations": re.compile(r"@(?:Entity|Table|ManyToOne|OneToMany)\b"),
}


class JavaDetector:
    def __init__(self, profile_registry: ProfileRegistry) -> None:
        self.profile_registry = profile_registry

    @staticmethod
    def is_java_project(root: Path) -> bool:
        return any((root / marker).exists() for marker in _JAVA_BUILD_MARKERS)

    def detect(self, root: Path) -> dict[str, object]:
        module_files = self._discover_java_modules(root)
        frameworks = self._discover_java_frameworks(module_files)
        spring = self._discover_spring_metadata(root)
        framework_profiles = tuple(
            JavaFrameworkProfile(framework=framework, detected=detected, evidence=tuple(evidence))
            for framework, detected, evidence in frameworks
        )
        profile_spec = self.profile_registry.get("java")
        profile = JavaProfile(frameworks=framework_profiles) if profile_spec is None else JavaProfile(
            frameworks=framework_profiles,
            scanners=profile_spec.scanners,
            parsers=profile_spec.parsers,
            metric_providers=profile_spec.metric_providers,
            cards=profile_spec.cards,
            policy_extensions=profile_spec.policy_extensions,
            cache_behavior=profile_spec.cache_behavior,
        )
        return {
            "module_count": len(module_files),
            "multi_module": len(module_files) > 1,
            "modules": [module.relative_to(root).as_posix() for module in module_files],
            "frameworks": [entry.framework.value for entry in profile.frameworks if entry.detected],
            "framework_evidence": {entry.framework.value: list(entry.evidence) for entry in profile.frameworks if entry.detected},
            "profile": {
                "scanners": list(profile.scanners),
                "parsers": list(profile.parsers),
                "metric_providers": list(profile.metric_providers),
                "cards": list(profile.cards),
                "policy_extensions": list(profile.policy_extensions),
                "cache_behavior": profile.cache_behavior,
            },
            "spring": spring,
        }

    @staticmethod
    def _discover_java_modules(root: Path) -> list[Path]:
        markers = {"pom.xml", "build.gradle", "build.gradle.kts"}
        module_files: list[Path] = []
        for marker in markers:
            module_files.extend(root.rglob(marker))
        unique = sorted({path.parent for path in module_files})
        return unique or [root]

    def _discover_java_frameworks(self, modules: list[Path]) -> list[tuple[JavaFramework, bool, list[str]]]:
        build_files: list[Path] = []
        for module in modules:
            for name in ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"):
                candidate = module / name
                if candidate.exists():
                    build_files.append(candidate)
        consolidated = "\n".join(DiscoveryHelper.safe_read_text(path) for path in build_files)
        return [
            (
                JavaFramework.spring,
                bool(_SPRING_COORDINATE_RE.search(consolidated)),
                self._framework_evidence(build_files, _SPRING_COORDINATE_RE),
            ),
            (
                JavaFramework.spring_boot,
                "spring-boot" in consolidated.lower() or "org.springframework.boot" in consolidated.lower(),
                self._framework_evidence(build_files, re.compile(r"(spring-boot|org\.springframework\.boot)", re.IGNORECASE)),
            ),
            (
                JavaFramework.micronaut,
                bool(_MICRONAUT_COORDINATE_RE.search(consolidated)),
                self._framework_evidence(build_files, _MICRONAUT_COORDINATE_RE),
            ),
            (
                JavaFramework.quarkus,
                bool(_QUARKUS_COORDINATE_RE.search(consolidated)),
                self._framework_evidence(build_files, _QUARKUS_COORDINATE_RE),
            ),
            (
                JavaFramework.jakarta_ee,
                bool(_JAKARTA_COORDINATE_RE.search(consolidated)),
                self._framework_evidence(build_files, _JAKARTA_COORDINATE_RE),
            ),
        ]

    def _discover_spring_metadata(self, root: Path) -> dict[str, object]:
        sources = list(root.rglob("*.java"))
        indicators: dict[str, bool] = {
            "security_modules": False,
            "actuator": False,
            "jpa_hibernate": False,
            "validation": False,
        }
        annotation_hits: dict[str, int] = {key: 0 for key in _SPRING_ANNOTATION_PATTERNS}
        for src in sources[:500]:
            text = DiscoveryHelper.safe_read_text(src)
            if not text:
                continue
            for key, pattern in _SPRING_ANNOTATION_PATTERNS.items():
                if pattern.search(text):
                    annotation_hits[key] += 1
            lower = text.lower()
            if "spring-security" in lower or "@enablewebsecurity" in lower:
                indicators["security_modules"] = True
            if "spring-boot-starter-actuator" in lower or "/actuator" in lower:
                indicators["actuator"] = True
            if "hibernate" in lower or "@entity" in lower:
                indicators["jpa_hibernate"] = True
            if "@valid" in text or "@validated" in text:
                indicators["validation"] = True
        return {**indicators, "annotation_hits": annotation_hits}

    @staticmethod
    def _framework_evidence(files: list[Path], pattern: re.Pattern[str]) -> list[str]:
        evidence: list[str] = []
        for file in files:
            text = DiscoveryHelper.safe_read_text(file)
            if pattern.search(text):
                evidence.append(file.name)
        return evidence[:20]
