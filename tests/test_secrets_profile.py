from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from codegauge.cli import app
from codegauge.bootstrap.factory import ScanApplicationServices
from codegauge.config.config import load_config
from codegauge.domain.models import Category, Finding, Language, Project, ScanResult, Severity
from codegauge.policy import CodeGaugePolicyEngine, PolicyReason, PolicyStatus
from codegauge.scoring.engine import CodeGaugeScoringEngine
from codegauge.scoring.models import NormalizedMetric, ScoreCategory
from codegauge.services.report_normalizer import finding_fingerprint, sanitize_raw_payload

runner = CliRunner()


def _score_card(metrics: list[NormalizedMetric]):
    return CodeGaugeScoringEngine().score(metrics)


def test_secret_redaction_uses_hashes() -> None:
    payload = {"secret_value": "abcd1234efgh5678", "token": "tok_1234567890", "safe": "value"}
    sanitized, truncated, redacted, _ = sanitize_raw_payload(
        payload,
        redact=True,
        max_bytes_per_finding=4096,
        remaining_global_bytes=4096,
    )
    assert truncated is False
    assert redacted is True
    assert str(sanitized["secret_value"]).startswith("<redacted_sha256:")
    assert str(sanitized["token"]).startswith("<redacted_sha256:")


def test_secret_fingerprint_is_deterministic_without_raw_secret_value() -> None:
    base = Finding(
        tool="gitleaks",
        rule_id="real_secret_exposure",
        severity=Severity.high,
        category=Category.security,
        language=Language.general,
        file=Path("src/app.py"),
        line=10,
        message="Secret detected in source.",
        raw_payload={"secret_real": True, "secret_value": "first"},
    )
    changed = base.model_copy(update={"raw_payload": {"secret_real": True, "secret_value": "second"}})
    assert finding_fingerprint(base) == finding_fingerprint(changed)


def test_policy_fails_for_secret_and_private_key_findings() -> None:
    engine = CodeGaugePolicyEngine()
    metrics = [
        NormalizedMetric(
            category=ScoreCategory.security,
            severity=Severity.high,
            count=1,
            score_hint=1.0,
            source="gitleaks",
        )
    ]
    policy = engine.evaluate(
        score_card=_score_card(metrics),
        metrics=metrics,
        scanner_failures=0,
        parser_missing=0,
        invalid_findings=0,
        invalid_paths=0,
        real_secret_findings=1,
        private_key_findings=1,
    )
    assert policy.status == PolicyStatus.fail
    assert PolicyReason.real_secret_exposure in policy.reasons
    assert PolicyReason.private_key_material in policy.reasons


def test_baseline_init_rejects_real_secret_findings(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj"
    project.mkdir()

    class _Orchestrator:
        @staticmethod
        def run(_project: Project):
            now = datetime.now(UTC)
            finding = Finding(
                tool="gitleaks",
                rule_id="real_secret_exposure",
                severity=Severity.high,
                category=Category.security,
                language=Language.general,
                file=Path("app.py"),
                line=1,
                message="real secret",
                raw_payload={"secret_real": True},
            )
            return [
                ScanResult(
                    scanner_name="gitleaks",
                    started_at=now,
                    completed_at=now,
                    duration_ms=1.0,
                    findings=[finding],
                    success=True,
                    metadata={},
                )
            ]

    services_obj = type(
        "Services",
        (),
        {
            "project": Project(name=project.name, path=project, language_hints=[Language.general]),
            "orchestrator": _Orchestrator(),
        },
    )()

    monkeypatch.setattr("codegauge.cli.build_scan_services_with_config", lambda _p, _c: services_obj)
    result = runner.invoke(app, ["baseline", "init", str(project)])
    assert result.exit_code == 3
    assert "baseline acceptance is prohibited for real secret findings" in result.stderr


def test_secrets_scan_command_json_shape(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj2"
    project.mkdir()

    class _Orchestrator:
        @staticmethod
        def run(_project: Project):
            now = datetime.now(UTC)
            finding = Finding(
                tool="secrets_heuristic",
                rule_id="weak_secret_management",
                severity=Severity.medium,
                category=Category.security,
                language=Language.general,
                file=Path("config/.env.example"),
                line=None,
                message="Sensitive file/path naming indicates secret storage risk.",
                raw_payload={"secret_real": False},
            )
            return [
                ScanResult(
                    scanner_name="secrets_heuristic",
                    started_at=now,
                    completed_at=now,
                    duration_ms=1.0,
                    findings=[finding],
                    success=True,
                    metadata={"scanner_input_file_count": 1},
                )
            ]

    services_obj = type(
        "Services",
        (),
        {
            "project": Project(name=project.name, path=project, language_hints=[Language.general], metadata={}),
            "config": type(
                "C",
                (),
                {
                    "report_root": project / "CodeGauge",
                    "payload": type(
                        "P",
                        (),
                        {
                            "capture_full_raw": False,
                            "redact": True,
                            "max_bytes_global": 1024 * 1024,
                            "max_bytes_per_finding": 4096,
                        },
                    )(),
                    "open_report": False,
                },
            )(),
            "orchestrator": _Orchestrator(),
        },
    )()

    monkeypatch.setattr(
        "codegauge.cli._build_secrets_services",
        lambda _p, _c, include_history, force_history, include_fixtures: services_obj,
    )
    monkeypatch.setattr("codegauge.cli_handlers.scan.StaticSiteBuilder.build", lambda _self: None)
    monkeypatch.setattr(
        "codegauge.cli_handlers.scan.ScanArtifactStore.persist_scan_artifacts",
        lambda self, **kwargs: None,
    )
    monkeypatch.setattr("codegauge.cli_handlers.scan.ScanArtifactStore.load_project_scan_history", lambda self, _p: [])
    result = runner.invoke(app, ["secrets", "scan", str(project), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "secrets_summary" in payload
    assert "sections" in payload["secrets_summary"]


def test_secrets_scan_is_non_blocking_by_default(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj3"
    project.mkdir()

    class _Orchestrator:
        @staticmethod
        def run(_project: Project):
            now = datetime.now(UTC)
            finding = Finding(
                tool="gitleaks",
                rule_id="real_secret_exposure",
                severity=Severity.high,
                category=Category.security,
                language=Language.general,
                file=Path("app.py"),
                line=1,
                message="real secret",
                raw_payload={"secret_real": True},
            )
            return [
                ScanResult(
                    scanner_name="gitleaks",
                    started_at=now,
                    completed_at=now,
                    duration_ms=1.0,
                    findings=[finding],
                    success=True,
                    metadata={"scanner_input_file_count": 1},
                )
            ]

    services_obj = type(
        "Services",
        (),
        {
            "project": Project(name=project.name, path=project, language_hints=[Language.general], metadata={}),
            "config": type(
                "C",
                (),
                {
                    "report_root": project / "CodeGauge",
                    "payload": type(
                        "P",
                        (),
                        {
                            "capture_full_raw": False,
                            "redact": True,
                            "max_bytes_global": 1024 * 1024,
                            "max_bytes_per_finding": 4096,
                        },
                    )(),
                    "open_report": False,
                },
            )(),
            "orchestrator": _Orchestrator(),
        },
    )()
    monkeypatch.setattr(
        "codegauge.cli._build_secrets_services",
        lambda _p, _c, include_history, force_history, include_fixtures: services_obj,
    )
    monkeypatch.setattr("codegauge.cli_handlers.scan.StaticSiteBuilder.build", lambda _self: None)
    monkeypatch.setattr("codegauge.cli_handlers.scan.ScanArtifactStore.persist_scan_artifacts", lambda self, **kwargs: None)
    monkeypatch.setattr("codegauge.cli_handlers.scan.ScanArtifactStore.load_project_scan_history", lambda self, _p: [])
    result = runner.invoke(app, ["secrets", "scan", str(project), "--json"])
    assert result.exit_code == 0


def test_build_secrets_services_applies_fixture_excludes_and_history_gate(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj4"
    project.mkdir()
    cfg = load_config(project_path=project)

    captured: dict[str, object] = {}

    def fake_builder(path: Path, config):
        captured["exclude"] = list(config.exclude)
        captured["enabled_scanners"] = list(config.enabled_scanners)
        service = ScanApplicationServices(
            project_path=path,
            project=Project(name=path.name, path=path, language_hints=[Language.general], metadata={}),
            config=config,
            scanner_registry=None,  # type: ignore[arg-type]
            parser_registry=None,  # type: ignore[arg-type]
            orchestrator=None,  # type: ignore[arg-type]
        )
        return service

    monkeypatch.setattr("codegauge.cli.build_scan_services_with_config", fake_builder)
    from codegauge.cli import _build_secrets_services

    services = _build_secrets_services(project, cfg, include_history=True, force_history=False, include_fixtures=False)
    assert "tests/fixtures/**" in captured["exclude"]
    assert "git_history_secrets" in captured["enabled_scanners"]
    gate = services.project.metadata.get("history_scan_gate")
    assert isinstance(gate, dict)
    assert gate.get("requested") is True


def test_build_secrets_services_tracks_unavailable_secret_scanners(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj5"
    project.mkdir()
    cfg = load_config(project_path=project)

    monkeypatch.setattr("codegauge.cli.shutil.which", lambda name: None if name in {"gitleaks", "trufflehog"} else "/usr/bin/git")

    def fake_builder(path: Path, config):
        return ScanApplicationServices(
            project_path=path,
            project=Project(name=path.name, path=path, language_hints=[Language.general], metadata={}),
            config=config,
            scanner_registry=None,  # type: ignore[arg-type]
            parser_registry=None,  # type: ignore[arg-type]
            orchestrator=None,  # type: ignore[arg-type]
        )

    monkeypatch.setattr("codegauge.cli.build_scan_services_with_config", fake_builder)
    from codegauge.cli import _build_secrets_services

    services = _build_secrets_services(project, cfg, include_history=False, force_history=False, include_fixtures=False)
    unavailable = services.project.metadata.get("secret_scanner_unavailable")
    assert isinstance(unavailable, list)
    names = {row["scanner"] for row in unavailable}
    assert names == {"gitleaks", "trufflehog"}


def test_build_secrets_services_enables_general_language_hint(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj6"
    project.mkdir()
    cfg = load_config(project_path=project)

    def fake_builder(path: Path, config):
        return ScanApplicationServices(
            project_path=path,
            project=Project(name=path.name, path=path, language_hints=[], metadata={}),
            config=config,
            scanner_registry=None,  # type: ignore[arg-type]
            parser_registry=None,  # type: ignore[arg-type]
            orchestrator=None,  # type: ignore[arg-type]
        )

    monkeypatch.setattr("codegauge.cli.build_scan_services_with_config", fake_builder)
    from codegauge.cli import _build_secrets_services

    services = _build_secrets_services(project, cfg, include_history=False, force_history=False, include_fixtures=False)
    assert Language.general in services.project.language_hints
