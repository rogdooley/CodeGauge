from __future__ import annotations

from pathlib import Path
import sys

import pytest

from codegauge.domain.models import Category, Language, Project, Severity
from codegauge.parsers.bandit_parser import BanditParser
from codegauge.parsers.base import ScannerOutputInvalidError
from codegauge.scanners.bandit_scanner import BanditScanner
from codegauge.services.parser_registry import ParserRegistry
from codegauge.services.scan_orchestrator import ScanOrchestrator
from codegauge.services.scanner_registry import ScannerRegistry


def test_bandit_parser_normalizes_findings() -> None:
    parser = BanditParser()
    stdout = """
{
  "results": [
    {
      "filename": "./src/a.py",
      "test_id": "B101",
      "issue_text": "Use of assert detected",
      "issue_severity": "HIGH",
      "line_number": 7
    }
  ]
}
"""
    findings = parser.parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "B101"
    assert finding.category == Category.security
    assert finding.severity == Severity.high
    assert finding.file == Path("src/a.py")
    assert finding.line == 7


def test_bandit_parser_rejects_malformed_json() -> None:
    parser = BanditParser()
    with pytest.raises(ScannerOutputInvalidError):
        parser.parse("not-json", "", Path.cwd())


def test_bandit_command_generation(tmp_path: Path) -> None:
    scanner = BanditScanner(extra_args=["-x", "tests"])
    command = scanner.build_command(tmp_path)
    assert command[:6] == ["bandit", "-r", str(tmp_path), "-f", "json", "--exit-zero"]
    assert command[-2:] == ["-x", "tests"]


def test_bandit_file_list_respects_exclude_patterns(tmp_path: Path) -> None:
    src_file = tmp_path / "src" / "app.py"
    src_file.parent.mkdir(parents=True)
    src_file.write_text("print('ok')\n")
    test_file = tmp_path / "tests" / "test_app.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text("assert True\n")

    scanner = BanditScanner(extra_args=["-x", "tests"])
    command = scanner.build_command_for_files(tmp_path, [src_file, test_file])

    assert str(src_file) in command
    assert str(test_file) not in command


class GoodOutputBanditScanner(BanditScanner):
    def is_available(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files) -> list[str]:
        return [
            sys.executable,
            "-c",
            "import json; print(json.dumps({'results':[{'filename':'a.py','test_id':'B101','issue_text':'assert used','issue_severity':'LOW','line_number':2}]}))",
        ]


def test_orchestrator_parses_bandit_findings(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("assert True\n")
    project = Project(name=tmp_path.name, path=tmp_path, language_hints=[Language.python])
    registry = ScannerRegistry([GoodOutputBanditScanner()])
    orchestrator = ScanOrchestrator(registry, ParserRegistry([BanditParser()]))
    results = orchestrator.run(project)
    assert len(results) == 1
    assert results[0].success is True
    assert len(results[0].findings) == 1
    assert results[0].findings[0].rule_id == "B101"
    assert results[0].findings[0].category == Category.security
