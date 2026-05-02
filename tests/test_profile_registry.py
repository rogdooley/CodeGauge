from __future__ import annotations

from codegauge.profiles import ProfileRegistry


def test_profile_registry_registers_builtins() -> None:
    registry = ProfileRegistry.with_builtins()
    names = {profile.name for profile in registry.all()}
    assert names == {
        "python",
        "django",
        "java",
        "javascript",
        "typescript",
        "php",
        "go",
        "infrastructure",
        "secrets",
    }


def test_profile_registry_profile_shape() -> None:
    registry = ProfileRegistry.with_builtins()
    java = registry.get("java")
    assert java is not None
    assert "spotbugs" in java.scanners
    assert "opengrep_java_parser" in java.parsers
    assert "java_cache" in java.cards
    assert java.cache_behavior == "aggressive"
