from __future__ import annotations

import json
from pathlib import Path

from codegauge.scanners.secrets_heuristic_scanner import SecretsHeuristicScanner


def _run(scanner: SecretsHeuristicScanner, project: Path):
    result = scanner.execute(project)
    payload = json.loads(result.stdout)
    return payload


def test_heuristic_scanner_drops_allowlisted_token_names(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    (project / "settings.py").write_text('csrf_token = "tok_abcdefghijklmnopqrstuvwxyz"\n', encoding="utf-8")

    payload = _run(SecretsHeuristicScanner(), project)
    assert payload["findings"] == []
    assert payload["scalar_metrics"]["secrets_allowlisted"] == 1


def test_heuristic_scanner_emits_probable_for_multi_signal_secret(tmp_path: Path) -> None:
    project = tmp_path / "repo2"
    project.mkdir()
    (project / "settings.py").write_text('api_key = "AKIA1234567890ABCDEF"\n', encoding="utf-8")

    payload = _run(SecretsHeuristicScanner(), project)
    findings = payload["findings"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["type"] == "probable_secret_exposure"
    assert finding["confidence"] == "probable"
    assert finding["signals"]["credential_format"] is True
    assert "credential_format" in finding["signal_labels"]


def test_heuristic_scanner_emits_weak_for_sensitive_path(tmp_path: Path) -> None:
    project = tmp_path / "repo3"
    project.mkdir()
    env_file = project / ".env"
    env_file.write_text("ENV=dev\n", encoding="utf-8")

    findings = _run(SecretsHeuristicScanner(), project)["findings"]
    assert any(item["type"] == "sensitive_path" and item["confidence"] == "weak" for item in findings)


def test_heuristic_scanner_marks_pem_marker_as_probable(tmp_path: Path) -> None:
    project = tmp_path / "repo4"
    project.mkdir()
    (project / "keys.pem").write_text("-----BEGIN PRIVATE KEY-----\n", encoding="utf-8")

    payload = _run(SecretsHeuristicScanner(), project)
    findings = payload["findings"]
    assert len(findings) >= 1
    pem = next(item for item in findings if item.get("line") == 1)
    assert pem["type"] == "probable_secret_exposure"
    assert pem["signals"]["pem_markers"] is True
    assert "pem_markers" in pem["signal_labels"]
    assert payload["scalar_metrics"]["secrets_candidates_seen"] >= 1
