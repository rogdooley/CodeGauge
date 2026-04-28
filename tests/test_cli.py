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
    assert Path(payload["reports_dir"]).is_absolute()
    assert Path(payload["site_dir"]).is_absolute()


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


def test_scan_human_output_shows_java_cache_summary(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "proj2_java"
    project.mkdir()
    (project / "pom.xml").write_text("<project/>")
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
    assert result.exit_code == 0
    assert "Java cache: 0 hits / 1 misses" in result.stdout
    assert "Miss reasons: manifest_missing=1" in result.stdout


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
    assert "global" in payload["parser_summary"]
    assert "per_scanner" in payload["parser_summary"]
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
    def explode(_path):
        raise RuntimeError("boom")

    monkeypatch.setattr("codegauge.cli.build_scan_services", explode)
    result = runner.invoke(app, ["scan", ".", "--fail-on-policy"])
    assert result.exit_code == 3


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
