from __future__ import annotations

from pathlib import Path

from codegauge.services.scanner_registry import ScannerRegistry
from codegauge.scanners import RuffScanner, BanditScanner


def test_registry_filters_by_language() -> None:
    registry = ScannerRegistry([RuffScanner()])
    scanners = registry.scanners_for_language("python")
    assert any(scanner.scanner_name == "ruff" for scanner in scanners)


def test_disabled_scanner_excluded_from_resolution() -> None:
    registry = ScannerRegistry([RuffScanner()], disabled_names={"ruff"})
    scanners = registry.enabled_scanners(["python"])
    assert scanners == []


def test_empty_enabled_scanners_means_all_supported() -> None:
    registry = ScannerRegistry([RuffScanner(), BanditScanner()], enabled_names=set())
    scanners = registry.enabled_scanners(["python"])
    assert {scanner.scanner_name for scanner in scanners} == {"ruff", "bandit"}
