from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class InfrastructureProfile:
    name: str = "infrastructure"
    frameworks: tuple[str, ...] = ("infrastructure",)
    scanners: tuple[str, ...] = (
        "opengrep_infra",
        "dockerfile_scan",
        "compose_scan",
        "quadlet_scan",
        "reverse_proxy_scan",
        "terraform_scan",
        "shellcheck",
    )
    parsers: tuple[str, ...] = (
        "opengrep_infra_parser",
        "dockerfile_scan_parser",
        "compose_scan_parser",
        "quadlet_scan_parser",
        "reverse_proxy_scan_parser",
        "terraform_scan_parser",
        "shellcheck_parser",
    )
    metric_providers: tuple[str, ...] = ("scalar", "findings")
    cards: tuple[str, ...] = (
        "container_hardening",
        "reverse_proxy_posture",
        "infrastructure_exposure",
        "secrets_hygiene",
        "runtime_isolation",
        "iac_safety",
        "shell_hygiene",
    )
    policy_extensions: tuple[str, ...] = ("infrastructure_baseline",)
    cache_behavior: str = "stateless"
