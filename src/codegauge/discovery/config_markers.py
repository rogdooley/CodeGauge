from __future__ import annotations

from pathlib import Path

PYTHON_MARKERS: frozenset[str] = frozenset(
    {
        "pyproject.toml",
        "ruff.toml",
        ".ruff.toml",
        "pyrightconfig.json",
        ".bandit",
        "setup.cfg",
        "tox.ini",
    }
)

JAVASCRIPT_MARKERS: frozenset[str] = frozenset(
    {
        "eslint.config.js",
        "eslint.config.cjs",
        "eslint.config.mjs",
        "eslint.config.ts",
        "tsconfig.json",
    }
)

JAVA_MARKERS: frozenset[str] = frozenset(
    {
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "checkstyle.xml",
        "spotbugs-exclude.xml",
    }
)

PHP_MARKERS: frozenset[str] = frozenset(
    {
        "phpstan.neon",
        "phpstan.neon.dist",
        "psalm.xml",
        "composer.json",
    }
)

GO_MARKERS: frozenset[str] = frozenset(
    {
        "go.mod",
        ".golangci.yml",
        ".golangci.yaml",
    }
)

ALL_CONFIG_MARKERS: frozenset[str] = frozenset().union(
    PYTHON_MARKERS,
    JAVASCRIPT_MARKERS,
    JAVA_MARKERS,
    PHP_MARKERS,
    GO_MARKERS,
)

ALL_GLOB_MARKERS: tuple[str, ...] = (
    ".eslintrc*",
)


def has_recognized_config_marker(project_root: Path) -> bool:
    for marker in ALL_CONFIG_MARKERS:
        if (project_root / marker).exists():
            return True
    for pattern in ALL_GLOB_MARKERS:
        if any(project_root.glob(pattern)):
            return True
    return False
