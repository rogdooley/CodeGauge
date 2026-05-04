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


def test_heuristic_scanner_does_not_flag_identifier_name_alone(tmp_path: Path) -> None:
    project = tmp_path / "repo5"
    project.mkdir()
    (project / "auth.py").write_text('password = "short"\naccess_token = "token"\n', encoding="utf-8")

    payload = _run(SecretsHeuristicScanner(), project)
    assert payload["findings"] == []


def test_heuristic_scanner_suppresses_excluded_identifier_names(tmp_path: Path) -> None:
    project = tmp_path / "repo6"
    project.mkdir()
    (project / "auth.py").write_text(
        'password_hash = "a3f5d7c9e1b2a4d6f8c0e2a4b6d8f0a2"\nmin_password_length = "64"\n',
        encoding="utf-8",
    )

    payload = _run(SecretsHeuristicScanner(), project)
    assert payload["findings"] == []


def test_heuristic_scanner_ignores_placeholder_values_in_example_env(tmp_path: Path) -> None:
    project = tmp_path / "repo7"
    project.mkdir()
    (project / ".env.example").write_text(
        'API_KEY="CHANGE_ME"\nCLIENT_SECRET="placeholder"\nACCESS_TOKEN="<generate>"\n',
        encoding="utf-8",
    )

    payload = _run(SecretsHeuristicScanner(), project)
    assert payload["findings"] == []


def test_heuristic_scanner_flags_realistic_secret_in_example_env(tmp_path: Path) -> None:
    project = tmp_path / "repo9"
    project.mkdir()
    (project / ".env.example").write_text('API_KEY="AKIA1234567890ABCDEF"\n', encoding="utf-8")

    payload = _run(SecretsHeuristicScanner(), project)
    assert any(item["type"] == "probable_secret_exposure" for item in payload["findings"])


def test_heuristic_scanner_ignores_test_vendor_dist_and_minified_files(tmp_path: Path) -> None:
    project = tmp_path / "repo8"
    (project / "tests").mkdir(parents=True)
    (project / "vendor").mkdir(parents=True)
    (project / "dist").mkdir(parents=True)
    (project / "tests" / "test_auth.py").write_text('api_key = "AKIA1234567890ABCDEF"\n', encoding="utf-8")
    (project / "vendor" / "lib.js").write_text('api_key = "AKIA1234567890ABCDEF"\n', encoding="utf-8")
    (project / "dist" / "bundle.js").write_text('api_key = "AKIA1234567890ABCDEF"\n', encoding="utf-8")
    (project / "app.min.js").write_text('api_key = "AKIA1234567890ABCDEF"\n', encoding="utf-8")

    payload = _run(SecretsHeuristicScanner(), project)
    assert payload["findings"] == []


def test_python_config_reads_are_not_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo10"
    project.mkdir()
    (project / "app.py").write_text(
        "api_key = settings.meili_api_key\napi_key = os.getenv('MEILI_API_KEY')\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert payload["findings"] == []


def test_python_default_literal_fallback_is_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo11"
    project.mkdir()
    (project / "app.py").write_text(
        "import os\napi_key = os.getenv('MEILI_API_KEY', 'AKIA1234567890ABCDEF')\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert any(item["message"].startswith("Potential hardcoded secret default fallback") for item in payload["findings"])


def test_python_sink_logging_and_response_leaks_are_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo12"
    project.mkdir()
    (project / "app.py").write_text(
        "import json\n\n"
        "def emit(token: str):\n"
        "    logger.info(token)\n"
        "    print(token)\n"
        "    json.dump({'token': token}, None)\n"
        "    return {'api_key': token}\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert any("sink call" in item["message"] for item in payload["findings"])
    assert any("response leak" in item["message"] for item in payload["findings"])


def test_python_parameter_and_attribute_names_not_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo13"
    project.mkdir()
    (project / "app.py").write_text(
        "def foo(api_key: str):\n"
        "    self.api_key = api_key\n"
        "    password_hash = api_key\n"
        "    credential_id = 'abc-123'\n"
        "    credential_blob = b'1234'\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert payload["findings"] == []


def test_url_bearer_rule_public_token_redirect_medium(tmp_path: Path) -> None:
    project = tmp_path / "repo14"
    project.mkdir()
    (project / "app.py").write_text(
        "import secrets\n"
        "def handler():\n"
        "    public_token = secrets.token_urlsafe(32)\n"
        "    return RedirectResponse(url=f\"/x?public_token={public_token}\")\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    finding = next(item for item in payload["findings"] if item["type"] == "intentional_bearer_issuance_url_transport")
    assert finding["severity"] == "medium"
    assert finding["subtype"] == "public_access_token"


def test_url_bearer_rule_invite_redirect_medium(tmp_path: Path) -> None:
    project = tmp_path / "repo15"
    project.mkdir()
    (project / "app.py").write_text(
        "def create_invite_code():\n"
        "    return 'abc'\n"
        "def handler():\n"
        "    invite_code = create_invite_code()\n"
        "    return redirect('/ok?invite_code=' + invite_code)\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert any(
        item["type"] == "intentional_bearer_issuance_url_transport" and item["subtype"] == "invite_capability_code"
        for item in payload["findings"]
    )


def test_url_bearer_rule_reset_redirect_medium_and_high(tmp_path: Path) -> None:
    project = tmp_path / "repo16"
    project.mkdir()
    (project / "app.py").write_text(
        "def generate_reset_token():\n"
        "    return 'abc'\n"
        "def a():\n"
        "    reset_token_a = generate_reset_token()\n"
        "    return RedirectResponse(url=f\"/r?reset_token={reset_token_a}\")\n"
        "def b():\n"
        "    reset_token_b = generate_reset_token()  # multi-use 30 day ttl full url logging telemetry\n"
        "    return RedirectResponse(url=f\"/r?reset_token={reset_token_b}\")\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    severities = [
        item["severity"] for item in payload["findings"] if item["type"] == "intentional_bearer_issuance_url_transport"
    ]
    assert "medium" in severities
    assert "high" in severities


def test_url_bearer_rule_non_findings_for_flash_csrf_cursor_path_and_docs(tmp_path: Path) -> None:
    project = tmp_path / "repo17"
    project.mkdir()
    (project / "app.py").write_text(
        "def issue_token():\n"
        "    return 'abc'\n"
        "def ok():\n"
        "    flash_id = issue_token()\n"
        "    csrf_token = issue_token()\n"
        "    cursor = issue_token()\n"
        "    a = RedirectResponse(url=f\"/x?flash_id={flash_id}\")\n"
        "    b = RedirectResponse(url=f\"/x?csrf_token={csrf_token}\")\n"
        "    c = RedirectResponse(url=f\"/x?cursor={cursor}\")\n"
        "    return {'url': f'/s/{flash_id}'}\n",
        encoding="utf-8",
    )
    (project / "README.md").write_text(
        "public_token = issue_token()\nreturn RedirectResponse(url=f\"/x?public_token={public_token}\")\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert not any(item["type"] == "intentional_bearer_issuance_url_transport" for item in payload["findings"])
