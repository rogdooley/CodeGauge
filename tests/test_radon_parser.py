from __future__ import annotations

from pathlib import Path
import sys

from codegauge.domain.models import Language, Project
from codegauge.parsers.radon_parser import RadonParser
from codegauge.scanners.radon_scanner import RadonScanner
from codegauge.services.metrics import MetricsExtractor
from codegauge.services.parser_registry import ParserRegistry
from codegauge.services.scan_orchestrator import ScanOrchestrator
from codegauge.services.scanner_registry import ScannerRegistry
from codegauge.scoring.models import ScoreCategory


def test_radon_parser_extracts_scalar_metrics_only() -> None:
    parser = RadonParser()
    stdout = (
        '{"cc":{"src/a.py":[{"name":"f","type":"function","complexity":11,"rank":"C"}]},'
        '"mi":{"src/a.py":74.0}}'
    )
    findings = parser.parse(stdout, "", Path.cwd())
    assert findings == []
    metadata = parser.parse_metadata(stdout, "", Path.cwd())
    scalar = metadata["scalar_metrics"]
    assert scalar["average_complexity"] == 11.0
    assert scalar["worst_complexity"] == 11
    assert scalar["complexity_distribution"] == {"C": 1}
    assert scalar["complexity_grade"] == "C"
    assert scalar["maintainability_index"] == 74.0
    assert scalar["maintainability_grade"] == "B"


def test_radon_parser_extracts_mi_from_object_entries() -> None:
    parser = RadonParser()
    stdout = (
        '{"cc":{"src/a.py":[{"name":"f","type":"function","complexity":7,"rank":"B"}]},'
        '"mi":{"src/a.py":{"mi":81.25,"rank":"A"},"src/b.py":{"mi":68.75,"rank":"B"}}}'
    )
    metadata = parser.parse_metadata(stdout, "", Path.cwd())
    scalar = metadata["scalar_metrics"]
    assert scalar["maintainability_index"] == 75.0
    assert scalar["maintainability_grade"] == "B"


class StubRadonScanner(RadonScanner):
    def is_available(self) -> bool:
        return True

    def build_command(self, project_path: Path) -> list[str]:
        return [
            sys.executable,
            "-c",
            (
                "import json; print(json.dumps({"
                "'cc': {'src/a.py':[{'name':'f','type':'function','complexity':9,'rank':'B'}]},"
                "'mi': {'src/a.py': 81.0}"
                "}))"
            ),
        ]

    def execute(self, project_path: Path, files=None):
        # Use base scanner execute behavior on the synthetic command.
        from codegauge.scanners.base import Scanner

        return Scanner.execute(self, project_path)


def test_radon_scalar_metrics_reach_scoring_inputs(tmp_path: Path) -> None:
    project = Project(name=tmp_path.name, path=tmp_path, language_hints=[Language.python])
    orchestrator = ScanOrchestrator(ScannerRegistry([StubRadonScanner()]), ParserRegistry([RadonParser()]))
    results = orchestrator.run(project)
    assert len(results) == 1
    assert results[0].success is True
    scalar = results[0].metadata.get("scalar_metrics")
    assert isinstance(scalar, dict)
    assert scalar["maintainability_index"] == 81.0

    metrics = MetricsExtractor().extract_from_scan_results(results)
    maintainability_metric = next(metric for metric in metrics if metric.category == ScoreCategory.maintainability)
    assert maintainability_metric.scalar_name == "maintainability_index"
    assert maintainability_metric.scalar_value == 81.0
