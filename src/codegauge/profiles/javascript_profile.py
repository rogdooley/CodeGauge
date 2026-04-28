from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class JavaScriptProfile:
    name: str = "javascript"
    frameworks: tuple[str, ...] = ("javascript",)
    scanners: tuple[str, ...] = (
        "eslint",
        "npm_audit",
        "js_coverage",
        "opengrep_js",
    )
    parsers: tuple[str, ...] = (
        "eslint_parser",
        "npm_audit_parser",
        "js_coverage_parser",
        "opengrep_js_parser",
    )
    metric_providers: tuple[str, ...] = ("scalar", "findings")
    cards: tuple[str, ...] = ("framework_cards",)
    policy_extensions: tuple[str, ...] = ("frontend_supply_chain",)
    cache_behavior: str = "partial"


@dataclass(frozen=True)
class TypeScriptProfile:
    name: str = "typescript"
    frameworks: tuple[str, ...] = ("typescript",)
    scanners: tuple[str, ...] = (
        "eslint",
        "typescript_diagnostics",
        "npm_audit",
        "js_coverage",
        "opengrep_js",
    )
    parsers: tuple[str, ...] = (
        "eslint_parser",
        "typescript_diagnostics_parser",
        "npm_audit_parser",
        "js_coverage_parser",
        "opengrep_js_parser",
    )
    metric_providers: tuple[str, ...] = ("scalar", "findings")
    cards: tuple[str, ...] = ("framework_cards",)
    policy_extensions: tuple[str, ...] = ("frontend_supply_chain", "typescript_strictness")
    cache_behavior: str = "partial"
