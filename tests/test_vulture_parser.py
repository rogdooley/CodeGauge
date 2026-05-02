from __future__ import annotations

from pathlib import Path
import sys
from types import SimpleNamespace

from codegauge.domain.models import Category, Language, Project, Severity
from codegauge.parsers.vulture_parser import VultureParser
from codegauge.scanners.vulture_scanner import VultureScanner
from codegauge.services.parser_registry import ParserRegistry
from codegauge.services.scan_orchestrator import ScanOrchestrator
from codegauge.services.scanner_registry import ScannerRegistry


def test_vulture_parser_normalizes_findings() -> None:
    parser = VultureParser()
    stdout = (
        '[{"filename":"./src/app.py","first_line":7,"size":2,"name":"unused_fn","type":"function"}]'
    )
    findings = parser.parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == Category.dead_code
    assert finding.severity == Severity.low
    assert finding.file == Path("src/app.py")
    assert finding.line == 7


class StubVultureScanner(VultureScanner):
    def is_available(self) -> bool:
        return True

    def build_command(self, project_path: Path) -> list[str]:
        return [
            sys.executable,
            "-c",
            "import json; print(json.dumps([{'filename':'src/a.py','first_line':3,'name':'x','type':'variable','size':1}]))",
        ]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files) -> list[str]:
        return self.build_command(project_path)


def test_vulture_findings_flow_through_orchestrator(tmp_path: Path) -> None:
    project = Project(name=tmp_path.name, path=tmp_path, language_hints=[Language.python])
    orchestrator = ScanOrchestrator(ScannerRegistry([StubVultureScanner()]), ParserRegistry([VultureParser()]))
    results = orchestrator.run(project)
    assert len(results) == 1
    assert results[0].success is True
    assert len(results[0].findings) == 1
    assert results[0].findings[0].category == Category.dead_code


def test_vulture_empty_nonzero_treated_as_success(tmp_path: Path, monkeypatch) -> None:
    scanner = VultureScanner()
    project = Project(name=tmp_path.name, path=tmp_path, language_hints=[Language.python])
    parser_registry = ParserRegistry([VultureParser()])

    monkeypatch.setattr(
        "codegauge.scanners.vulture_scanner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=3, stdout="", stderr=""),
    )

    orchestrator = ScanOrchestrator(ScannerRegistry([scanner]), parser_registry)
    results = orchestrator.run(project)
    assert len(results) == 1
    assert results[0].success is True
    assert results[0].findings == []
