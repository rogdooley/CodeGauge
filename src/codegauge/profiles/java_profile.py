from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class JavaFramework(str, Enum):
    spring = "spring"
    spring_boot = "spring_boot"
    micronaut = "micronaut"
    quarkus = "quarkus"
    jakarta_ee = "jakarta_ee"


@dataclass(frozen=True)
class JavaFrameworkProfile:
    framework: JavaFramework
    detected: bool
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class JavaProfile:
    name: str = "java"
    scanners: tuple[str, ...] = (
        "spotbugs",
        "pmd",
        "checkstyle",
        "errorprone",
        "jacoco",
        "dependency_check",
        "opengrep_java",
    )
    parsers: tuple[str, ...] = (
        "spotbugs_parser",
        "pmd_parser",
        "checkstyle_parser",
        "errorprone_parser",
        "jacoco_parser",
        "dependency_check_parser",
        "opengrep_java_parser",
    )
    metric_providers: tuple[str, ...] = ("scalar", "findings")
    cards: tuple[str, ...] = ("java_metrics", "java_cache", "framework_cards")
    policy_extensions: tuple[str, ...] = ("spring_posture",)
    cache_behavior: str = "aggressive"
    frameworks: tuple[JavaFrameworkProfile, ...] = field(default_factory=tuple)
