from __future__ import annotations

from pathlib import Path

import pytest

from codegauge.domain.models import Finding
from codegauge.parsers.base import ScannerParser
from codegauge.parsers.bandit_parser import BanditParser
from codegauge.parsers.ruff_parser import RuffParser
from codegauge.services.parser_registry import DuplicateParserRegistrationError, ParserRegistry


class DummyParser(ScannerParser):
    parser_name = "dummy_parser"
    supported_scanners = ("dummy",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> list[Finding]:
        return []


class DuplicateDummyParser(ScannerParser):
    parser_name = "duplicate_dummy"
    supported_scanners = ("dummy",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> list[Finding]:
        return []


def test_parser_registry_register_and_lookup() -> None:
    registry = ParserRegistry([RuffParser(), BanditParser(), DummyParser()])
    assert registry.get("ruff") is not None
    assert registry.get("bandit") is not None
    assert registry.get("dummy") is not None
    assert registry.get("not_real") is None
    assert "ruff_parser" in registry.available_parsers()
    assert "bandit" in registry.available_scanners()


def test_duplicate_parser_registration_fails() -> None:
    registry = ParserRegistry([DummyParser()])
    with pytest.raises(DuplicateParserRegistrationError):
        registry.register(DuplicateDummyParser())
