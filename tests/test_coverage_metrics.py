from __future__ import annotations

from pathlib import Path

from codegauge.domain.models import Language, Project
from codegauge.parsers.coverage_parser import CoverageParser
from codegauge.scanners.coverage_scanner import CoverageScanner
from codegauge.services.parser_registry import ParserRegistry
from codegauge.services.scan_orchestrator import ScanOrchestrator
from codegauge.services.scanner_registry import ScannerRegistry
from codegauge.services.metrics import MetricsExtractor
from codegauge.scoring.engine import CodeGaugeScoringEngine
from codegauge.scoring.models import ScoreCategory


class StubCoverageScanner(CoverageScanner):
    def is_available(self) -> bool:
        return True

    def build_command(self, project_path: Path) -> list[str]:
        return [
            "python",
            "-c",
            "import json; print(json.dumps({'totals': {'percent_covered': 77.7}}))",
        ]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files) -> list[str]:
        return self.build_command(project_path)


class MissingCoverageDataScanner(CoverageScanner):
    def is_available(self) -> bool:
        return True

    def build_command(self, project_path: Path) -> list[str]:
        _ = project_path
        return ["coverage", "json", "-o", "-"]

    def execute(self, project_path: Path, files=None):
        return super().execute(project_path, files=files)


def test_coverage_metric_flows_to_scoring_inputs(tmp_path: Path) -> None:
    project = Project(name=tmp_path.name, path=tmp_path, language_hints=[Language.python])
    scanner_registry = ScannerRegistry([StubCoverageScanner()])
    parser_registry = ParserRegistry([CoverageParser()])
    orchestrator = ScanOrchestrator(scanner_registry, parser_registry)

    results = orchestrator.run(project)
    assert len(results) == 1
    assert results[0].success is True
    assert results[0].metadata["scalar_metrics"]["coverage_percent"] == 77.7

    metrics = MetricsExtractor().extract_from_scan_results(results)
    coverage_metric = next(metric for metric in metrics if metric.category == ScoreCategory.coverage)
    assert coverage_metric.scalar_name == "coverage_percent"
    assert coverage_metric.scalar_value == 77.7

    card = CodeGaugeScoringEngine().score(metrics)
    coverage_score = next(score for score in card.category_scores if score.category == ScoreCategory.coverage)
    assert coverage_score.score == 77.7


def test_coverage_no_data_is_treated_as_zero_not_failure(tmp_path: Path, monkeypatch) -> None:
    project = Project(name=tmp_path.name, path=tmp_path, language_hints=[Language.python])

    class _Done:
        returncode = 2
        stdout = ""
        stderr = "No data to report."

    monkeypatch.setattr("codegauge.scanners.coverage_scanner.subprocess.run", lambda *a, **k: _Done())

    scanner_registry = ScannerRegistry([MissingCoverageDataScanner()])
    parser_registry = ParserRegistry([CoverageParser()])
    orchestrator = ScanOrchestrator(scanner_registry, parser_registry)
    results = orchestrator.run(project)

    assert len(results) == 1
    assert results[0].success is True
    assert results[0].metadata.get("coverage_missing_data") is True
    assert results[0].metadata.get("scalar_metrics", {}).get("coverage_percent") == 0.0
