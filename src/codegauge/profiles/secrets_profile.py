from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SecretsProfile:
    name: str = "secrets"
    frameworks: tuple[str, ...] = ("general",)
    scanners: tuple[str, ...] = (
        "gitleaks",
        "trufflehog",
        "secrets_heuristic",
        "git_history_secrets",
    )
    parsers: tuple[str, ...] = (
        "gitleaks_parser",
        "trufflehog_parser",
        "secrets_heuristic_parser",
        "git_history_secrets_parser",
    )
    metric_providers: tuple[str, ...] = ("findings",)
    cards: tuple[str, ...] = (
        "secrets_hygiene",
        "historical_secret_exposure",
        "key_material_exposure",
        "credential_management",
    )
    policy_extensions: tuple[str, ...] = ("secrets_fail_closed", "secrets_baseline_prohibition")
    cache_behavior: str = "stateless"
