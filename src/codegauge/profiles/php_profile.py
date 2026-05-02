from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PHPProfile:
    name: str = "php"
    frameworks: tuple[str, ...] = ("php",)
    scanners: tuple[str, ...] = (
        "phpstan",
        "composer_audit",
        "opengrep_php",
        "phpcs",
    )
    parsers: tuple[str, ...] = (
        "phpstan_parser",
        "composer_audit_parser",
        "opengrep_php_parser",
        "phpcs_parser",
    )
    metric_providers: tuple[str, ...] = ("scalar", "findings")
    cards: tuple[str, ...] = ("framework_cards", "security_focus")
    policy_extensions: tuple[str, ...] = ("php_supply_chain",)
    cache_behavior: str = "partial"
