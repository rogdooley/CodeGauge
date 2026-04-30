from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from codegauge.domain.models import Category, Finding, Language, ScanResult, Severity
from codegauge.policy import PolicyReason, PolicyStatus, QualityPolicyResult
from typer.testing import CliRunner

from codegauge.cli import _compact_scanner_raw_output, app


runner = CliRunner()


def test_show_config_prints_resolved_json(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / ".codegauge.toml").write_text('default_timeout_seconds = 33\n')

    result = runner.invoke(app, ["show-config", str(project)])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["default_timeout_seconds"] == 33
    assert Path(payload["report_root"]).is_absolute()
    assert Path(payload["state_root"]).is_absolute()


def test_scan_runs_with_stub_scanners(tmp_path: Path) -> None:
    project = tmp_path / "proj2"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')

    result = runner.invoke(app, ["scan", str(project)])
    assert result.exit_code == 0
    assert "Ran 1 scanners for proj2" in result.stdout
    assert "Overall score:" in result.stdout
    assert "Grade:" in result.stdout
    assert "Policy status:" in result.stdout
    assert "Debt summary:" in result.stdout
    assert "Java cache:" not in result.stdout


def test_scan_fails_closed_when_no_scanners_resolved(tmp_path: Path) -> None:
    project = tmp_path / "empty_proj"
    project.mkdir()
    result = runner.invoke(app, ["scan", str(project)])
    assert result.exit_code == 3
    assert "no scanners resolved for project" in result.stderr


def test_scan_json_fails_closed_when_no_scanners_resolved(tmp_path: Path) -> None:
    project = tmp_path / "empty_proj_json"
    project.mkdir()
    result = runner.invoke(app, ["scan", str(project), "--json"])
    assert result.exit_code == 3
    assert "no scanners resolved for project" in result.stderr


def test_scan_human_output_shows_contract_violation_for_unsupported_scanner(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj2_java"
    project.mkdir()
    (project / "pom.xml").write_text("<project/>")
    src = project / "src" / "main" / "java"
    src.mkdir(parents=True)
    (src / "App.java").write_text("class App {}\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["spotbugs"]\n')

    def fake_run(*args, **kwargs):
        class _Done:
            returncode = 0
            stdout = ""
            stderr = ""
        artifact = project / "target" / "spotbugsXml.xml"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("<BugCollection/>")
        return _Done()

    monkeypatch.setattr("codegauge.scanners.java_build_scanner_base.subprocess.run", fake_run)
    result = runner.invoke(app, ["scan", str(project)])
    assert result.exit_code == 4
    assert "Policy status: FAIL" in result.stdout
    assert "Policy reasons: scanner_failure" in result.stdout


def test_scan_json_output_shape(tmp_path: Path) -> None:
    project = tmp_path / "proj3"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')

    result = runner.invoke(app, ["scan", str(project), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["project"] == "proj3"
    assert payload["scanner_count"] == 1
    assert "duration_ms" in payload
    assert payload["schema_version"] == "2.0.0"
    assert payload["fingerprint_version"] == "1"
    assert payload["message_normalizer_version"] == "1"
    assert "report_sha256" in payload
    assert "parser_summary" in payload
    assert "scanner_stats" in payload
    assert isinstance(payload["scanner_stats"], list)
    assert "policy_resolution" in payload
    assert "security_summary" in payload
    assert "classifier" in payload
    assert "framework" in payload["policy_resolution"]
    assert "global" in payload["parser_summary"]
    assert "per_scanner" in payload["parser_summary"]
    assert payload["classifier"]["name"] == "security_classifier"
    assert payload["classifier"]["version"] == "1.0.0"
    assert "finding_count" in payload
    assert "invalid_findings" in payload
    assert "invalid_paths" in payload
    assert "parse_failures" in payload
    assert "parser_missing" in payload
    assert "scanner_failures" in payload
    assert "score_card" in payload
    assert "policy" in payload
    assert "overall_score" in payload["score_card"]
    assert "grade" in payload["score_card"]
    assert "dedupe" in payload["score_card"]
    assert "baseline" in payload["score_card"]
    assert "status" in payload["policy"]
    assert "reasons" in payload["policy"]
    assert isinstance(payload["results"], list)
    assert payload["results"][0]["scanner_name"] == "ruff"
    assert "success" in payload["results"][0]
    assert "error_code" in payload["results"][0]
    assert "finding_count" in payload["results"][0]
    assert "duration_ms" in payload["results"][0]


def test_scan_json_includes_classifier_for_single_bandit_scanner(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj_bandit"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')

    now = datetime.now(UTC)
    bandit_result = ScanResult(
        scanner_name="bandit",
        started_at=now,
        completed_at=now,
        duration_ms=1.0,
        findings=[
            Finding(
                tool="bandit",
                rule_id="B603",
                severity=Severity.high,
                category=Category.security,
                language=Language.python,
                file=Path("src/app.py"),
                line=12,
                message="subprocess call",
            )
        ],
        success=True,
        metadata={},
    )

    monkeypatch.setattr("codegauge.services.scan_orchestrator.ScanOrchestrator.run", lambda _self, _project: [bandit_result])
    result = runner.invoke(app, ["scan", str(project), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["classifier"]["name"] == "security_classifier"
    assert payload["classifier"]["version"] == "1.0.0"


def test_scan_json_includes_classifier_for_mixed_scanners(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj_mixed"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')

    now = datetime.now(UTC)
    results = [
        ScanResult(
            scanner_name="bandit",
            started_at=now,
            completed_at=now,
            duration_ms=1.0,
            findings=[
                Finding(
                    tool="bandit",
                    rule_id="B310",
                    severity=Severity.medium,
                    category=Category.security,
                    language=Language.python,
                    file=Path("tests/smoke_test.py"),
                    line=8,
                    message="urlopen usage",
                )
            ],
            success=True,
            metadata={},
        ),
        ScanResult(
            scanner_name="opengrep",
            started_at=now,
            completed_at=now,
            duration_ms=1.0,
            findings=[
                Finding(
                    tool="opengrep",
                    rule_id="SEC.SQLI.1",
                    severity=Severity.high,
                    category=Category.security,
                    language=Language.python,
                    file=Path("src/db.py"),
                    line=21,
                    message="Possible SQL injection",
                )
            ],
            success=True,
            metadata={},
        ),
        ScanResult(
            scanner_name="ruff",
            started_at=now,
            completed_at=now,
            duration_ms=1.0,
            findings=[
                Finding(
                    tool="ruff",
                    rule_id="F401",
                    severity=Severity.low,
                    category=Category.dead_code,
                    language=Language.python,
                    file=Path("src/app.py"),
                    line=2,
                    message="unused import",
                )
            ],
            success=True,
            metadata={},
        ),
    ]
    monkeypatch.setattr("codegauge.services.scan_orchestrator.ScanOrchestrator.run", lambda _self, _project: results)
    result = runner.invoke(app, ["scan", str(project), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["classifier"]["name"] == "security_classifier"
    assert payload["classifier"]["version"] == "1.0.0"


def test_scan_json_includes_classifier_when_no_security_findings(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj_no_security"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')

    now = datetime.now(UTC)
    lint_result = ScanResult(
        scanner_name="ruff",
        started_at=now,
        completed_at=now,
        duration_ms=1.0,
        findings=[
            Finding(
                tool="ruff",
                rule_id="E302",
                severity=Severity.low,
                category=Category.lint,
                language=Language.python,
                file=Path("src/app.py"),
                line=1,
                message="expected 2 blank lines",
            )
        ],
        success=True,
        metadata={},
    )
    monkeypatch.setattr("codegauge.services.scan_orchestrator.ScanOrchestrator.run", lambda _self, _project: [lint_result])
    result = runner.invoke(app, ["scan", str(project), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["classifier"]["name"] == "security_classifier"
    assert payload["classifier"]["version"] == "1.0.0"
    assert payload["security_summary"]["by_class"]["runtime_security"] == 0


def test_scan_json_verbose_includes_execution_details(tmp_path: Path) -> None:
    project = tmp_path / "proj4"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')

    result = runner.invoke(app, ["scan", str(project), "--json", "--verbose"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    entry = payload["results"][0]
    assert "metadata" in entry
    assert "stdout" in entry
    assert "stderr" in entry
    assert "command" in entry
    assert "exit_code" in entry


def test_scan_human_output_shows_reason_codes_for_warn(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "proj5"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')

    def fake_evaluate(*args, **kwargs):
        return QualityPolicyResult(
            status=PolicyStatus.warn,
            reasons=[PolicyReason.high_security_findings, PolicyReason.low_score],
            violations=[],
            warnings=["x"],
            summary="warn",
        )

    monkeypatch.setattr("codegauge.cli.CodeGaugePolicyEngine.evaluate", fake_evaluate)
    result = runner.invoke(app, ["scan", str(project)])
    assert result.exit_code == 0
    assert "Policy status: WARN" in result.stdout
    assert "Policy reasons: high_security_findings, low_score" in result.stdout


def test_scan_fail_on_policy_exit_code_pass(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj6"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')

    def fake_evaluate(*args, **kwargs):
        return QualityPolicyResult(
            status=PolicyStatus.pass_,
            reasons=[],
            violations=[],
            warnings=[],
            summary="pass",
        )

    monkeypatch.setattr("codegauge.cli.CodeGaugePolicyEngine.evaluate", fake_evaluate)
    result = runner.invoke(app, ["scan", str(project), "--fail-on-policy"])
    assert result.exit_code == 0


def test_scan_fail_on_policy_exit_code_warn(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj7"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')

    def fake_evaluate(*args, **kwargs):
        return QualityPolicyResult(
            status=PolicyStatus.warn,
            reasons=[PolicyReason.low_score],
            violations=[],
            warnings=["low score"],
            summary="warn",
        )

    monkeypatch.setattr("codegauge.cli.CodeGaugePolicyEngine.evaluate", fake_evaluate)
    result = runner.invoke(app, ["scan", str(project), "--fail-on-policy"])
    assert result.exit_code == 1


def test_scan_fail_on_policy_exit_code_fail(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj8"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')

    def fake_evaluate(*args, **kwargs):
        return QualityPolicyResult(
            status=PolicyStatus.fail,
            reasons=[PolicyReason.scanner_failure],
            violations=["scanner failures present"],
            warnings=[],
            summary="fail",
        )

    monkeypatch.setattr("codegauge.cli.CodeGaugePolicyEngine.evaluate", fake_evaluate)
    result = runner.invoke(app, ["scan", str(project), "--fail-on-policy"])
    assert result.exit_code == 2


def test_scan_fail_on_policy_exit_code_internal(monkeypatch) -> None:
    def explode(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("codegauge.cli.build_scan_services_with_config", explode)
    result = runner.invoke(app, ["scan", ".", "--fail-on-policy"])
    assert result.exit_code == 6


def test_fastapi_policy_resolution_disables_django_scanners(tmp_path: Path) -> None:
    project = tmp_path / "fastapi_proj"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')
    result = runner.invoke(app, ["scan", str(project), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["policy_resolution"]["language"] == "python"
    assert payload["policy_resolution"]["framework"] == "fastapi"
    assert payload["policy_resolution"]["framework_confidence"] >= 0.7
    assert payload["policy_resolution"]["disabled"]["django_template_scan"] == "framework_incompatible"


def test_flask_policy_resolution_disables_django_scanners(tmp_path: Path) -> None:
    project = tmp_path / "flask_proj"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')
    result = runner.invoke(app, ["scan", str(project), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["policy_resolution"]["framework"] == "flask"
    assert payload["policy_resolution"]["framework_confidence"] >= 0.7
    assert payload["policy_resolution"]["disabled"]["django_settings_scan"] == "framework_incompatible"


def test_django_policy_resolution_enables_django_scanners(tmp_path: Path) -> None:
    project = tmp_path / "django_proj"
    project.mkdir()
    (project / "manage.py").write_text("import os\nos.environ['DJANGO_SETTINGS_MODULE']='x.settings'\n")
    (project / "settings.py").write_text("INSTALLED_APPS = []\nDEBUG = True\n")
    (project / "views.py").write_text("from django.http import HttpResponse\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')
    result = runner.invoke(app, ["scan", str(project), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["policy_resolution"]["framework"] == "django"
    assert payload["policy_resolution"]["framework_confidence"] >= 0.95
    assert "django_template_scan" in payload["policy_resolution"]["enabled"]


def test_venv_files_are_excluded_from_scanner_input(tmp_path: Path) -> None:
    project = tmp_path / "venv_proj"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / "app.py").write_text("x = 1\n")
    (project / ".venv").mkdir()
    (project / ".venv" / "ignored.py").write_text("y = 2\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["ruff"]\n')
    result = runner.invoke(app, ["scan", str(project), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    stats = {row["scanner_name"]: row for row in payload["scanner_stats"]}
    assert stats["ruff"]["scanner_input_file_count"] == 1


def test_disabled_scanner_not_executed(tmp_path: Path) -> None:
    project = tmp_path / "disabled_proj"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / "app.py").write_text("x = 1\n")
    (project / ".codegauge.toml").write_text(
        'enabled_scanners = ["ruff"]\ndisabled_scanners = ["bandit"]\n'
    )
    result = runner.invoke(app, ["scan", str(project), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    scanner_names = {row["scanner_name"] for row in payload["scanner_stats"]}
    assert "ruff" in scanner_names
    assert "bandit" not in scanner_names


def test_pyright_scanner_runs_successfully(tmp_path: Path) -> None:
    project = tmp_path / "contract_proj"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / "app.py").write_text("x = 1\n")
    (project / ".codegauge.toml").write_text('enabled_scanners = ["pyright"]\n')
    result = runner.invoke(app, ["scan", str(project), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["scanner_stats"][0]["scanner_name"] == "pyright"
    assert payload["scanner_stats"][0]["success"] is True


def test_compact_opengrep_raw_output_omits_large_stdout() -> None:
    now = datetime.now(UTC)
    result = ScanResult(
        scanner_name="opengrep",
        started_at=now,
        completed_at=now,
        duration_ms=5.0,
        success=True,
        findings=[
            Finding(
                tool="opengrep",
                rule_id="SEC.X",
                severity=Severity.high,
                category=Category.security,
                language=Language.python,
                file=Path("src/a.py"),
                line=1,
                message="x",
            )
        ],
        metadata={"command": ["opengrep"], "stdout": "huge-sarif", "stderr": "", "exit_code": 0},
    )
    compact = _compact_scanner_raw_output(result)
    assert "stdout" not in compact
    assert compact["finding_count"] == 1
    assert compact["rules"] == ["SEC.X"]
    assert compact["sample_messages"][0]["message"] == "x"


def test_compact_opengrep_raw_output_caps_sample_messages() -> None:
    now = datetime.now(UTC)
    findings = [
        Finding(
            tool="opengrep",
            rule_id=f"SEC.{index}",
            severity=Severity.high,
            category=Category.security,
            language=Language.python,
            file=Path(f"src/{index}.py"),
            line=index,
            message=f"message {index}",
        )
        for index in range(30)
    ]
    result = ScanResult(
        scanner_name="opengrep",
        started_at=now,
        completed_at=now,
        duration_ms=5.0,
        success=True,
        findings=findings,
        metadata={"command": ["opengrep"], "stdout": "huge-sarif", "stderr": "", "exit_code": 0},
    )
    compact = _compact_scanner_raw_output(result)
    assert len(compact["sample_messages"]) == 25


def test_scan_open_flag_attempts_to_open_portal(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "open_proj"
    project.mkdir()
    report_root = tmp_path / "CodeGauge"
    (project / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.0.1'\n")
    (project / ".codegauge.toml").write_text(
        f'report_root = "{report_root.as_posix()}"\nenabled_scanners = ["ruff"]\nopen_report = false\n'
    )

    called: dict[str, str] = {}

    def fake_open(target: Path):
        called["target"] = str(target)
        return True, "opened"

    monkeypatch.setattr("codegauge.cli.open_in_browser", fake_open)
    result = runner.invoke(app, ["scan", str(project), "--open"])
    assert result.exit_code == 0
    assert called["target"].endswith("index.html")


def test_open_command_missing_portal_is_helpful(tmp_path: Path) -> None:
    project = tmp_path / "open_missing"
    project.mkdir()
    report_root = tmp_path / "CodeGauge"
    (project / ".codegauge.toml").write_text(f'report_root = "{report_root.as_posix()}"\n')
    result = runner.invoke(app, ["open", str(project)])
    assert result.exit_code == 0
    assert "No report portal found" in result.stdout


def test_cache_status_uses_state_root_cache_path(tmp_path: Path) -> None:
    project = tmp_path / "cache_state"
    project.mkdir()
    state_root = tmp_path / "state"
    (project / "pom.xml").write_text("<project/>")
    (project / "src" / "main" / "java").mkdir(parents=True)
    (project / "src" / "main" / "java" / "App.java").write_text("class App {}")
    (project / ".codegauge.toml").write_text(f'state_root = "{state_root.as_posix()}"\n')
    result = runner.invoke(app, ["cache", "status", str(project)])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert str(state_root) in payload["cache_root"]
