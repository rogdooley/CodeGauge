from __future__ import annotations

import sys
from pathlib import Path

from codegauge.domain.models import Language, Project
from codegauge.parsers.bandit_parser import BanditParser
from codegauge.parsers.ruff_parser import RuffParser
from codegauge.scanners.bandit_scanner import BanditScanner
from codegauge.scanners.ruff_scanner import RuffScanner
from codegauge.services.parser_registry import ParserRegistry
from codegauge.services.scan_orchestrator import ScanOrchestrator
from codegauge.services.scanner_registry import ScannerRegistry


class RegistryRuffScanner(RuffScanner):
    def is_available(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files) -> list[str]:
        return [
            sys.executable,
            "-c",
            "import json; print(json.dumps([{'code':'F401','message':'unused import','filename':'src/app.py','location':{'row':2,'column':1}}]))",
        ]


class RegistryBanditScanner(BanditScanner):
    def is_available(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files) -> list[str]:
        return [
            sys.executable,
            "-c",
            "import json; print(json.dumps({'results':[{'filename':'src/app.py','test_id':'B101','issue_text':'assert usage','issue_severity':'LOW','line_number':4}]}))",
        ]


def test_registry_integration_for_ruff_and_bandit(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("import os\nassert True\n")
    project = Project(name=tmp_path.name, path=tmp_path, language_hints=[Language.python])
    scanner_registry = ScannerRegistry([RegistryRuffScanner(), RegistryBanditScanner()])
    parser_registry = ParserRegistry([RuffParser(), BanditParser()])
    orchestrator = ScanOrchestrator(scanner_registry, parser_registry)
    results = orchestrator.run(project)

    assert len(results) == 2
    by_name = {result.scanner_name: result for result in results}
    assert by_name["ruff"].success is True
    assert by_name["bandit"].success is True
    assert len(by_name["ruff"].findings) == 1
    assert len(by_name["bandit"].findings) == 1
    assert by_name["ruff"].findings[0].file == Path("src/app.py")
    assert by_name["bandit"].findings[0].file == Path("src/app.py")
