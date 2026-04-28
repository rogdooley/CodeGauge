from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codegauge.domain.models import Category, Language, Project, Severity
from codegauge.parsers.base import FindingPathInvalidError, ScannerOutputInvalidError
from codegauge.parsers.ruff_parser import RuffParser
from codegauge.scanners.ruff_scanner import RuffScanner
from codegauge.services.parser_registry import ParserRegistry
from codegauge.services.scan_orchestrator import ScanOrchestrator
from codegauge.services.scanner_registry import ScannerRegistry


def _python_project(path: Path) -> Project:
    return Project(name=path.name, path=path, language_hints=[Language.python])


def test_ruff_command_generation(tmp_path: Path) -> None:
    scanner = RuffScanner(extra_args=["--select", "F401"])
    command = scanner.build_command(tmp_path)
    assert command[:5] == ["ruff", "check", str(tmp_path), "--output-format", "json"]
    assert "--exit-zero" in command
    assert command[-2:] == ["--select", "F401"]


def test_ruff_json_parsing() -> None:
    parser = RuffParser()
    project_root = Path.cwd()
    absolute_file = (project_root / "src/app.py").resolve()
    stdout = """
[
  {
    "code": "F401",
    "message": "`os` imported but unused",
    "filename": "__ABS_PATH__",
    "location": {"row": 3, "column": 8},
    "end_location": {"row": 3, "column": 10}
  },
  {
    "code": "S101",
    "message": "Use of assert detected",
    "filename": "src/app.py",
    "location": {"row": 12, "column": 5},
    "end_location": {"row": 12, "column": 11}
  }
]
"""
    findings = parser.parse(stdout.replace("__ABS_PATH__", str(absolute_file)), "", project_root)
    assert len(findings) == 2
    assert findings[0].rule_id == "F401"
    assert findings[0].message == "`os` imported but unused"
    assert findings[0].file == Path("src/app.py")
    assert findings[0].line == 3
    assert findings[0].column == 8
    assert findings[0].category == Category.dead_code
    assert findings[0].severity == Severity.medium
    assert findings[1].category == Category.security
    assert findings[1].severity == Severity.high


def test_ruff_parser_rejects_malformed_json() -> None:
    parser = RuffParser()
    with pytest.raises(ScannerOutputInvalidError):
        parser.parse("not-json", "", Path.cwd())


def test_ruff_parser_rejects_path_outside_project(tmp_path: Path) -> None:
    parser = RuffParser()
    outside_file = (tmp_path.parent / "outside.py").resolve()
    payload = (
        '[{"code":"F401","message":"unused import","filename":"'
        + str(outside_file)
        + '","location":{"row":1,"column":1}}]'
    )
    with pytest.raises(FindingPathInvalidError):
        parser.parse(payload, "", tmp_path)


class BadOutputRuffScanner(RuffScanner):
    def is_available(self) -> bool:
        return True

    def build_command(self, project_path: Path) -> list[str]:
        return [sys.executable, "-c", "print('this is not json')"]


class GoodOutputRuffScanner(RuffScanner):
    def is_available(self) -> bool:
        return True

    def build_command(self, project_path: Path) -> list[str]:
        return [
            sys.executable,
            "-c",
            "import json; print(json.dumps([{'code':'F401','message':'unused import','filename':'a.py','location':{'row':1,'column':1}}]))",
        ]


def test_orchestrator_parses_ruff_findings(tmp_path: Path) -> None:
    scanner = GoodOutputRuffScanner()
    registry = ScannerRegistry([scanner])
    orchestrator = ScanOrchestrator(registry, ParserRegistry([RuffParser()]))
    results = orchestrator.run(_python_project(tmp_path))
    assert len(results) == 1
    assert results[0].success is True
    assert len(results[0].findings) == 1
    assert results[0].findings[0].rule_id == "F401"


def test_malformed_ruff_json_produces_output_invalid_error(tmp_path: Path) -> None:
    scanner = BadOutputRuffScanner()
    registry = ScannerRegistry([scanner])
    orchestrator = ScanOrchestrator(registry, ParserRegistry([RuffParser()]))
    results = orchestrator.run(_python_project(tmp_path))
    assert len(results) == 1
    assert results[0].success is False
    assert results[0].error_code == "scanner_output_invalid"
    assert results[0].metadata["error_code"] == "scanner_output_invalid"


class BadPathRuffScanner(RuffScanner):
    def is_available(self) -> bool:
        return True

    def build_command(self, project_path: Path) -> list[str]:
        outside = (project_path.parent / "outside.py").resolve()
        return [
            sys.executable,
            "-c",
            f"import json; print(json.dumps([{{'code':'F401','message':'unused import','filename':{outside.as_posix()!r},'location':{{'row':1,'column':1}}}}]))",
        ]


def test_invalid_finding_path_results_in_failed_scan(tmp_path: Path) -> None:
    scanner = BadPathRuffScanner()
    registry = ScannerRegistry([scanner])
    orchestrator = ScanOrchestrator(registry, ParserRegistry([RuffParser()]))
    results = orchestrator.run(_python_project(tmp_path))
    assert len(results) == 1
    assert results[0].success is False
    assert results[0].error_code == "finding_path_invalid"
    assert results[0].metadata.get("invalid_finding_count") == 1
    invalid_payload = results[0].metadata.get("invalid_finding_payload")
    assert isinstance(invalid_payload, dict)
    assert invalid_payload.get("path_normalization") == "invalid"
    assert "raw_file_path" in invalid_payload


def test_missing_ruff_binary_is_normalized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = RuffScanner()
    monkeypatch.setattr("codegauge.scanners.ruff_scanner.shutil.which", lambda _: None)
    registry = ScannerRegistry([scanner])
    orchestrator = ScanOrchestrator(registry, ParserRegistry([RuffParser()]))
    results = orchestrator.run(_python_project(tmp_path))
    assert len(results) == 1
    assert results[0].success is False
    assert results[0].error_code == "scanner_binary_missing"
    assert "binary not found" in (results[0].error or "")
