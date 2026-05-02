from __future__ import annotations

from codegauge.profiles import ProfileRegistry


def test_php_profile_shape() -> None:
    profile = ProfileRegistry.with_builtins().get("php")
    assert profile is not None
    assert "phpstan" in profile.scanners
    assert "composer_audit_parser" in profile.parsers


def test_go_profile_shape() -> None:
    profile = ProfileRegistry.with_builtins().get("go")
    assert profile is not None
    assert "go_vet" in profile.scanners
    assert "govulncheck_parser" in profile.parsers
