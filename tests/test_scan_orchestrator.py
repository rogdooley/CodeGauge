from __future__ import annotations

import sys
from pathlib import Path

from codegauge.domain.models import Finding
from codegauge.domain.models import Language, Project
from codegauge.parsers.base import ScannerParser
from codegauge.scanners.base import Scanner
from codegauge.services.parser_registry import ParserRegistry
from codegauge.services.scan_orchestrator import ScanOrchestrator
from codegauge.services.scanner_registry import ScannerRegistry


class CommandScanner(Scanner):
    scanner_name = "command"
    supported_languages = ["python"]

    def __init__(self, command: list[str], *, timeout_seconds: int = 120, available: bool = True) -> None:
        super().__init__(timeout_seconds=timeout_seconds)
        self._command = command
        self._available = available

    def is_available(self) -> bool:
        return self._available

    def build_command(self, project_path: Path) -> list[str]:
        return self._command


def _project(path: Path) -> Project:
    return Project(name=path.name, path=path, language_hints=[Language.python])


class CommandParser(ScannerParser):
    parser_name = "command_parser"
    supported_scanners = ("command",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> list[Finding]:
        return []


def test_scan_orchestrator_runs(tmp_path: Path) -> None:
    scanner = CommandScanner([sys.executable, "-c", "print('ok')"])
    registry = ScannerRegistry([scanner])
    orchestrator = ScanOrchestrator(registry, ParserRegistry([CommandParser()]))
    results = orchestrator.run(_project(tmp_path))
    assert isinstance(results, list)
    assert len(results) == 1
    assert results[0].success is True


def test_scanner_subprocess_failure_is_normalized(tmp_path: Path) -> None:
    scanner = CommandScanner([sys.executable, "-c", "import sys; sys.exit(7)"])
    registry = ScannerRegistry([scanner])
    orchestrator = ScanOrchestrator(registry, ParserRegistry())
    results = orchestrator.run(_project(tmp_path))
    assert len(results) == 1
    assert results[0].success is False
    assert results[0].error_code == "scanner_nonzero_exit"
    assert "code 7" in (results[0].error or "")
    assert results[0].metadata["exit_code"] == 7
    assert isinstance(results[0].metadata["command"], list)
    assert "stdout" in results[0].metadata
    assert "stderr" in results[0].metadata


def test_scanner_timeout_is_normalized(tmp_path: Path) -> None:
    scanner = CommandScanner(
        [sys.executable, "-c", "import time; time.sleep(2)"],
        timeout_seconds=1,
    )
    registry = ScannerRegistry([scanner])
    orchestrator = ScanOrchestrator(registry, ParserRegistry())
    results = orchestrator.run(_project(tmp_path))
    assert len(results) == 1
    assert results[0].success is False
    assert results[0].error_code == "scanner_timeout"
    assert "timed out" in (results[0].error or "")
    assert results[0].metadata["exit_code"] is None


def test_missing_external_scanner_binary_is_reported(tmp_path: Path) -> None:
    scanner = CommandScanner(["definitely-not-a-real-binary-codegauge"], available=True)
    registry = ScannerRegistry([scanner])
    orchestrator = ScanOrchestrator(registry, ParserRegistry())
    results = orchestrator.run(_project(tmp_path))
    assert len(results) == 1
    assert results[0].success is False
    assert results[0].error_code == "scanner_binary_missing"
    assert "binary not found" in (results[0].error or "")


def test_missing_parser_fails_closed(tmp_path: Path) -> None:
    scanner = CommandScanner([sys.executable, "-c", "print('[]')"])
    registry = ScannerRegistry([scanner])
    orchestrator = ScanOrchestrator(registry, ParserRegistry())
    results = orchestrator.run(_project(tmp_path))
    assert len(results) == 1
    assert results[0].success is False
    assert results[0].error_code == "scanner_parser_missing"
    assert "parser not registered for scanner" in (results[0].error or "")
    assert results[0].metadata["scanner_name"] == "command"
    assert results[0].metadata["expected_parser"] == "command_parser"
    assert "Register parser" in (results[0].metadata["remediation"] or "")
