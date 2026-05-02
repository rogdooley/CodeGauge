from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GoProfile:
    name: str = "go"
    frameworks: tuple[str, ...] = ("go",)
    scanners: tuple[str, ...] = (
        "go_vet",
        "staticcheck",
        "govulncheck",
        "go_coverage",
        "opengrep_go",
    )
    parsers: tuple[str, ...] = (
        "go_vet_parser",
        "staticcheck_parser",
        "govulncheck_parser",
        "go_coverage_parser",
        "opengrep_go_parser",
    )
    metric_providers: tuple[str, ...] = ("scalar", "findings")
    cards: tuple[str, ...] = ("framework_cards", "security_focus")
    policy_extensions: tuple[str, ...] = ("go_vuln_hardening",)
    cache_behavior: str = "partial"
