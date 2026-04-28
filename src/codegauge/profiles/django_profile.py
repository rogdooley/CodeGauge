from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DjangoProfile:
    name: str = "django"
    frameworks: tuple[str, ...] = ("django",)
    scanners: tuple[str, ...] = (
        "django_check_deploy",
        "django_settings_scan",
        "django_template_scan",
        "django_orm_health",
    )
    parsers: tuple[str, ...] = (
        "django_check_deploy_parser",
        "django_settings_scan_parser",
        "django_template_scan_parser",
        "django_orm_health_parser",
    )
    metric_providers: tuple[str, ...] = ("findings",)
    cards: tuple[str, ...] = ("framework_cards",)
    policy_extensions: tuple[str, ...] = ("django_hardening",)
    cache_behavior: str = "stateless"
