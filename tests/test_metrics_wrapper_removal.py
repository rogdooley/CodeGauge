from __future__ import annotations

from pathlib import Path


def test_legacy_finding_metrics_extractor_wrapper_removed() -> None:
    project_root = Path(__file__).resolve().parents[1]
    legacy = project_root / "src" / "codegauge" / "services" / "finding_metrics_extractor.py"
    assert not legacy.exists()
