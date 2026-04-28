from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PythonProfile:
    name: str = "python"
    frameworks: tuple[str, ...] = ("python",)
    scanners: tuple[str, ...] = (
        "ruff",
        "pyright",
        "coverage",
        "radon",
        "vulture",
        "bandit",
        "opengrep",
    )
    parsers: tuple[str, ...] = (
        "ruff_parser",
        "pyright_parser",
        "coverage_parser",
        "radon_parser",
        "vulture_parser",
        "bandit_parser",
        "opengrep_parser",
    )
    metric_providers: tuple[str, ...] = ("scalar", "findings")
    cards: tuple[str, ...] = ("metric_cards", "dedupe", "baseline")
    policy_extensions: tuple[str, ...] = ()
    cache_behavior: str = "stateless"
