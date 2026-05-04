from __future__ import annotations

import json
from pathlib import Path
import pytest

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


def test_intentional_capability_token_response_not_flagged_as_probable_secret(tmp_path: Path) -> None:
    project = tmp_path / "repo_fp1"
    project.mkdir()
    (project / "entry_service.py").write_text(
        "import secrets\n"
        "def create_public_link():\n"
        "    token = secrets.token_urlsafe(32)\n"
        "    return {'ok': True, 'token': token}\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert not any(item["type"] == "probable_secret_exposure" for item in payload["findings"])


def test_totp_enrollment_secret_display_js_not_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo_fp2"
    project.mkdir()
    (project / "totp.js").write_text(
        "function start() {\n"
        "  var secret = document.getElementById('totp-secret');\n"
        "  secret.textContent = payload.secret;\n"
        "}\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert payload["findings"] == []


def test_login_template_state_token_and_csrf_hidden_input_not_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo_fp3"
    project.mkdir()
    (project / "login.html").write_text(
        "<button data-login-state-token=\"{{ login_state_token }}\"></button>\n"
        "<input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token(request) }}\" />\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert payload["findings"] == []


def test_js_challenge_token_bootstrap_not_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo_fp5"
    project.mkdir()
    (project / "bootstrap.js").write_text(
        "window.bootstrap = window.bootstrap || {};\n"
        "window.bootstrap.challengeToken = payload.challengeToken;\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert payload["findings"] == []


def test_passkeys_js_challenge_token_assignment_not_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo_fp13"
    project.mkdir()
    (project / "passkeys.js").write_text(
        "async function beginPasskey(payload) {\n"
        "  const challenge_token = payload.challengeToken;\n"
        "  const publicKey = { challenge: challenge_token };\n"
        "  return navigator.credentials.get({ publicKey });\n"
        "}\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert payload["findings"] == []


def test_jsx_hidden_csrf_and_login_state_token_not_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo_fp6"
    project.mkdir()
    (project / "Login.jsx").write_text(
        "export function Login({ login_state_token, csrf_token }) {\n"
        "  return (\n"
        "    <form method=\"post\">\n"
        "      <input type=\"hidden\" name=\"csrf_token\" value={csrf_token} />\n"
        "      <input type=\"hidden\" name=\"login_state_token\" value={login_state_token} />\n"
        "    </form>\n"
        "  );\n"
        "}\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert payload["findings"] == []


def test_tsx_webauthn_challenge_assignment_not_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo_fp7"
    project.mkdir()
    (project / "Passkey.tsx").write_text(
        "export async function begin(payload: { challengeToken: string }) {\n"
        "  const publicKey: PublicKeyCredentialRequestOptions = {\n"
        "    challenge: payload.challengeToken as unknown as ArrayBuffer,\n"
        "  };\n"
        "  return navigator.credentials.get({ publicKey });\n"
        "}\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert payload["findings"] == []


def test_internal_auth_session_response_leak_still_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo_fp4"
    project.mkdir()
    (project / "auth.py").write_text(
        "def leak(access_token, session_token):\n"
        "    return {'access_token': access_token, 'session_token': session_token}\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert any(item["type"] == "probable_secret_exposure" and "response leak" in item["message"] for item in payload["findings"])


def test_python_challenge_token_response_leak_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo_fp8"
    project.mkdir()
    (project / "auth.py").write_text(
        "def leak(challenge_token):\n"
        "    return {'challenge_token': challenge_token}\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert any(item["type"] == "probable_secret_exposure" and "response leak" in item["message"] for item in payload["findings"])


def test_python_challenge_token_logging_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo_fp9"
    project.mkdir()
    (project / "auth.py").write_text(
        "def leak(logger, challenge_token):\n"
        "    logger.info(challenge_token)\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert any(item["type"] == "probable_secret_exposure" and "sink call" in item["message"] for item in payload["findings"])


def test_python_challenge_token_query_transport_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo_fp10"
    project.mkdir()
    (project / "auth.py").write_text(
        "import secrets\n"
        "def route():\n"
        "    challenge_token = secrets.token_urlsafe(16)\n"
        "    return RedirectResponse(url=f\"/verify?challenge_token={challenge_token}\")\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert any(item["type"] == "intentional_bearer_issuance_url_transport" for item in payload["findings"])


def test_backend_local_challenge_token_assignment_without_sink_or_transport_not_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo_fp11"
    project.mkdir()
    (project / "auth.py").write_text(
        "import secrets\n"
        "def build():\n"
        "    challenge_token = secrets.token_urlsafe(16)\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert payload["findings"] == []


def test_backend_redirectresponse_challenge_token_query_transport_is_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo_fp12"
    project.mkdir()
    (project / "auth.py").write_text(
        "import secrets\n"
        "def route():\n"
        "    challenge_token = secrets.token_urlsafe(16)\n"
        "    return RedirectResponse(url=f\"/verify?challenge_token={challenge_token}\")\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert any(item["type"] == "intentional_bearer_issuance_url_transport" for item in payload["findings"])


def test_unrelated_js_challenge_token_assignment_outside_webauthn_still_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo_fp14"
    project.mkdir()
    (project / "token.js").write_text(
        "challenge_token = 'AKIA1234567890ABCDEF';\n"
        "console.log(challenge_token);\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert any(item["type"] == "probable_secret_exposure" for item in payload["findings"])


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


def test_memexa_entries_pattern_intermediate_url_variable_redirectresponse(tmp_path: Path) -> None:
    project = tmp_path / "repo18"
    project.mkdir()
    (project / "entries.py").write_text(
        "import secrets\n"
        "def route():\n"
        "    public_token = secrets.token_urlsafe(24)\n"
        "    redirect_url = f\"/entries?public_token={public_token}\"\n"
        "    return RedirectResponse(url=redirect_url)\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert any(item["type"] == "intentional_bearer_issuance_url_transport" for item in payload["findings"])


def test_memexa_entries_pattern_url_for_plus_query_concat(tmp_path: Path) -> None:
    project = tmp_path / "repo19"
    project.mkdir()
    (project / "entries.py").write_text(
        "def issue_public_token():\n"
        "    return 'abc'\n"
        "def route():\n"
        "    public_token = issue_public_token()\n"
        "    target = url_for('entries') + '?public_token=' + public_token\n"
        "    return redirect(target)\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert any(item["type"] == "intentional_bearer_issuance_url_transport" for item in payload["findings"])


def test_memexa_conversation_pattern_query_dict_and_urlencode(tmp_path: Path) -> None:
    project = tmp_path / "repo20"
    project.mkdir()
    (project / "conversation.py").write_text(
        "def create_invite():\n"
        "    return 'abc'\n"
        "def route():\n"
        "    invite_code = create_invite()\n"
        "    params = {'invite_code': invite_code}\n"
        "    query = urlencode(params)\n"
        "    target = url_for('invite_created') + '?' + query\n"
        "    return RedirectResponse(url=target)\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert any(item["type"] == "intentional_bearer_issuance_url_transport" for item in payload["findings"])


def test_memexa_admin_invite_created_helper_built_url(tmp_path: Path) -> None:
    project = tmp_path / "repo21"
    project.mkdir()
    (project / "admin.py").write_text(
        "def create_invite():\n"
        "    return 'abc'\n"
        "def build_invite_created_url(invite_code):\n"
        "    return f\"/admin/invite_created?invite_code={invite_code}\"\n"
        "def route():\n"
        "    invite_code = create_invite()\n"
        "    redirect_url = build_invite_created_url(invite_code)\n"
        "    return redirect(redirect_url)\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert any(item["type"] == "intentional_bearer_issuance_url_transport" for item in payload["findings"])


def test_memexa_admin_created_helper_url_then_redirectresponse(tmp_path: Path) -> None:
    project = tmp_path / "repo22"
    project.mkdir()
    (project / "admin.py").write_text(
        "def issue_reset_token():\n"
        "    return 'abc'\n"
        "def make_created_redirect_url(reset_token):\n"
        "    return f\"/admin/created?reset_token={reset_token}\"\n"
        "def route():\n"
        "    reset_token = issue_reset_token()\n"
        "    url_value = make_created_redirect_url(reset_token)\n"
        "    return RedirectResponse(url=url_value)\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert any(item["type"] == "intentional_bearer_issuance_url_transport" for item in payload["findings"])


def test_sqlalchemy_text_fstring_is_flagged_as_unsafe_interpolated(tmp_path: Path) -> None:
    project = tmp_path / "repo23"
    project.mkdir()
    (project / "app.py").write_text(
        "from sqlalchemy import text\n"
        "def q(x):\n"
        "    stmt = text(f\"select * from users where id = {x}\")\n"
        "    return stmt\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    finding = next(item for item in payload["findings"] if item["type"] == "unsafe_dynamic_sql_construction")
    assert finding["classification"] == "UNSAFE_INTERPOLATED"


def test_sqlalchemy_text_concat_is_flagged_as_unsafe_interpolated(tmp_path: Path) -> None:
    project = tmp_path / "repo24"
    project.mkdir()
    (project / "app.py").write_text(
        "from sqlalchemy import text\n"
        "def q(user_input):\n"
        "    stmt = text(\"select * from users where name = '\" + user_input + \"'\")\n"
        "    return stmt\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    finding = next(item for item in payload["findings"] if item["type"] == "unsafe_dynamic_sql_construction")
    assert finding["classification"] == "UNSAFE_INTERPOLATED"


def test_sqlalchemy_text_percent_format_is_flagged_as_unsafe_interpolated(tmp_path: Path) -> None:
    project = tmp_path / "repo25"
    project.mkdir()
    (project / "app.py").write_text(
        "from sqlalchemy import text\n"
        "def q(x):\n"
        "    stmt = text(\"select * from users where id = %s\" % x)\n"
        "    return stmt\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    finding = next(item for item in payload["findings"] if item["type"] == "unsafe_dynamic_sql_construction")
    assert finding["classification"] == "UNSAFE_INTERPOLATED"


def test_sqlalchemy_text_dot_format_is_flagged_as_unsafe_interpolated(tmp_path: Path) -> None:
    project = tmp_path / "repo26"
    project.mkdir()
    (project / "app.py").write_text(
        "from sqlalchemy import text\n"
        "def q(x):\n"
        "    stmt = text(\"select * from users where id = {}\".format(x))\n"
        "    return stmt\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    finding = next(item for item in payload["findings"] if item["type"] == "unsafe_dynamic_sql_construction")
    assert finding["classification"] == "UNSAFE_INTERPOLATED"


def test_sqlalchemy_text_bound_parameter_is_not_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo27"
    project.mkdir()
    (project / "app.py").write_text(
        "from sqlalchemy import text\n"
        "def q(x, conn):\n"
        "    stmt = text(\"select * from users where id=:id\")\n"
        "    return conn.execute(stmt, {\"id\": x})\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert not any(item["type"] == "unsafe_dynamic_sql_construction" for item in payload["findings"])


def test_sqlalchemy_text_constant_literal_is_not_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo28"
    project.mkdir()
    (project / "app.py").write_text(
        "from sqlalchemy import text\n"
        "def q():\n"
        "    return text(\"select 1\")\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert not any(item["type"] == "unsafe_dynamic_sql_construction" for item in payload["findings"])


def test_non_sqlalchemy_text_fstring_is_not_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo29"
    project.mkdir()
    (project / "app.py").write_text(
        "def text(value):\n"
        "    return value\n"
        "def q(x):\n"
        "    return text(f\"select * from users where id = {x}\")\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    assert not any(item["type"] == "unsafe_dynamic_sql_construction" for item in payload["findings"])


def test_sqlalchemy_module_alias_text_fstring_is_flagged(tmp_path: Path) -> None:
    project = tmp_path / "repo30"
    project.mkdir()
    (project / "app.py").write_text(
        "import sqlalchemy as sa\n"
        "def q(x):\n"
        "    return sa.text(f\"select * from users where id = {x}\")\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    finding = next(item for item in payload["findings"] if item["type"] == "unsafe_dynamic_sql_construction")
    assert finding["classification"] == "UNSAFE_INTERPOLATED"


@pytest.mark.parametrize(
    ("name", "snippet", "expected_security", "expected_review"),
    [
        pytest.param(
            "memexa_sqlite_code_repository_34",
            "from sqlalchemy import text\n"
            "def q(q, language, params, conn):\n"
            "    where = ['1=1']\n"
            "    if q:\n"
            "        where.append('name = :q')\n"
            "    if language:\n"
            "        where.append('lang = :language')\n"
            "    return conn.execute(text(f\"SELECT * FROM t WHERE {' AND '.join(where)}\"), params)\n",
            False,
            True,
            id="memexa_sqlite_code_repository_34",
        ),
        pytest.param(
            "memexa_sqlite_search_repository_361",
            "from sqlalchemy import text\n"
            "def q(clauses, conn, params):\n"
            "    where_sql = ' AND '.join(clauses)\n"
            "    return conn.execute(text(f\"SELECT COUNT(*) FROM t WHERE {where_sql}\"), params)\n",
            False,
            True,
            id="memexa_sqlite_search_repository_361",
        ),
        pytest.param(
            "memexa_rate_limit_87",
            "from sqlalchemy import text\n"
            "def q(normalized, conn, params):\n"
            "    placeholders = ', '.join(f':id_{idx}' for idx in range(len(normalized)))\n"
            "    return conn.execute(text(f\"SELECT COUNT(*) FROM x WHERE identifier IN ({placeholders})\"), params)\n",
            False,
            True,
            id="memexa_rate_limit_87",
        ),
        pytest.param(
            "memexa_auth_270",
            "from sqlalchemy import text\n"
            "def q(conn):\n"
            "    reset_predicate = 'AND (:reset_cutoff IS NULL OR created_at > :reset_cutoff)'\n"
            "    return conn.execute(text('SELECT COUNT(*) FROM audit_logs ' + reset_predicate), {})\n",
            False,
            True,
            id="memexa_auth_270",
        ),
        pytest.param(
            "memexa_auth_291",
            "from sqlalchemy import text\n"
            "def q(conn):\n"
            "    reset_predicate = 'AND (:reset_cutoff IS NULL OR created_at > :reset_cutoff)'\n"
            "    return conn.execute(text('SELECT COUNT(*) FROM alerts ' + reset_predicate), {})\n",
            False,
            True,
            id="memexa_auth_291",
        ),
        pytest.param(
            "memexa_auth_369",
            "from sqlalchemy import text\n"
            "def q(conn):\n"
            "    reset_predicate = 'AND (:reset_cutoff IS NULL OR created_at > :reset_cutoff)'\n"
            "    return conn.execute(text('SELECT COUNT(*) FROM recent ' + reset_predicate), {})\n",
            False,
            True,
            id="memexa_auth_369",
        ),
        pytest.param(
            "memexa_auth_393",
            "from sqlalchemy import text\n"
            "def q(conn):\n"
            "    reset_predicate = 'AND (:reset_cutoff IS NULL OR created_at > :reset_cutoff)'\n"
            "    return conn.execute(text('SELECT COUNT(*) FROM active ' + reset_predicate), {})\n",
            False,
            True,
            id="memexa_auth_393",
        ),
        pytest.param(
            "memexa_timeline_182",
            "from sqlalchemy import text\n"
            "def q(conn):\n"
            "    return conn.execute(text('SELECT * FROM entries WHERE user_id = :user_id'), {'user_id': 1})\n",
            False,
            False,
            id="memexa_timeline_182",
        ),
        pytest.param(
            "memexa_unlock_login_59",
            "from sqlalchemy import text\n"
            "def q(normalized, conn, params):\n"
            "    placeholders = ', '.join(f':id_{idx}' for idx in range(len(normalized)))\n"
            "    return conn.execute(text(f\"SELECT COUNT(*) FROM login_attempts WHERE identifier IN ({placeholders})\"), params)\n",
            False,
            True,
            id="memexa_unlock_login_59",
        ),
        pytest.param(
            "memexa_migrate_86",
            "from sqlalchemy import text\n"
            "def _quote_ident(x):\n"
            "    return x\n"
            "def q(conn, table):\n"
            "    return conn.execute(text(f\"SELECT COUNT(*) FROM {_quote_ident(table)}\")).scalar_one()\n",
            False,
            True,
            id="memexa_migrate_86",
        ),
        pytest.param(
            "memexa_migrate_96",
            "from sqlalchemy import text\n"
            "def _quote_ident(x):\n"
            "    return x\n"
            "def q(conn, table, id_column):\n"
            "    return conn.execute(text(f\"SELECT COALESCE(MAX({_quote_ident(id_column)}), 0) FROM {_quote_ident(table)}\")).scalar_one()\n",
            False,
            True,
            id="memexa_migrate_96",
        ),
        pytest.param(
            "memexa_migrate_150",
            "from sqlalchemy import text\n"
            "def _quote_ident(x):\n"
            "    return x\n"
            "def q(table):\n"
            "    col_expr = 'id, name'\n"
            "    return text(f\"SELECT {col_expr} FROM {_quote_ident(table)}\")\n",
            False,
            True,
            id="memexa_migrate_150",
        ),
        pytest.param(
            "memexa_migrate_151",
            "from sqlalchemy import text\n"
            "def _quote_ident(x):\n"
            "    return x\n"
            "def q(table):\n"
            "    col_expr = 'id, name'\n"
            "    return text(f\"INSERT INTO {_quote_ident(table)} ({col_expr}) VALUES (:id, :name)\")\n",
            False,
            True,
            id="memexa_migrate_151",
        ),
    ],
)
def test_memexa_sqlalchemy_examples_classification(
    tmp_path: Path,
    name: str,
    snippet: str,
    expected_security: bool,
    expected_review: bool,
) -> None:
    project = tmp_path / name
    project.mkdir()
    (project / "app.py").write_text(snippet, encoding="utf-8")
    payload = _run(SecretsHeuristicScanner(), project)
    has_security = any(item["type"] == "unsafe_dynamic_sql_construction" for item in payload["findings"])
    has_review = any(item["type"] == "sqlalchemy_text_review_required" for item in payload["findings"])
    assert has_security is expected_security
    assert has_review is expected_review


def test_sqlalchemy_repeated_dynamic_where_fragments_cluster_together(tmp_path: Path) -> None:
    project = tmp_path / "cluster_repo1"
    project.mkdir()
    (project / "a.py").write_text(
        "from sqlalchemy import text\n"
        "def q(parts):\n"
        "    where_sql = ' AND '.join(parts)\n"
        "    return text(f\"SELECT * FROM t WHERE {where_sql}\")\n",
        encoding="utf-8",
    )
    (project / "b.py").write_text(
        "from sqlalchemy import text\n"
        "def q(parts):\n"
        "    where_sql = ' AND '.join(parts)\n"
        "    return text(f\"SELECT id FROM t WHERE {where_sql}\")\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    sql_findings = [f for f in payload["findings"] if f["type"] == "sqlalchemy_text_review_required"]
    assert len(sql_findings) == 2
    keys = {f["sqlalchemy_pattern_key"] for f in sql_findings}
    assert keys == {"dynamic_where_fragment"}
    fingerprints = {f["sqlalchemy_pattern_fingerprint"] for f in sql_findings}
    assert len(fingerprints) == 1


def test_sqlalchemy_dynamic_in_placeholder_expansion_has_own_key(tmp_path: Path) -> None:
    project = tmp_path / "cluster_repo2"
    project.mkdir()
    (project / "a.py").write_text(
        "from sqlalchemy import text\n"
        "def q(ids):\n"
        "    placeholders = ', '.join(f':id_{i}' for i in range(len(ids)))\n"
        "    return text(f\"SELECT * FROM t WHERE id IN ({placeholders})\")\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    finding = next(f for f in payload["findings"] if f["type"] == "sqlalchemy_text_review_required")
    assert finding["sqlalchemy_pattern_key"] == "dynamic_in_placeholder_expansion"


def test_sqlalchemy_quoted_identifier_builder_has_own_key(tmp_path: Path) -> None:
    project = tmp_path / "cluster_repo3"
    project.mkdir()
    (project / "a.py").write_text(
        "from sqlalchemy import text\n"
        "def _quote_ident(x):\n"
        "    return x\n"
        "def q(table):\n"
        "    return text(f\"SELECT COUNT(*) FROM {_quote_ident(table)}\")\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    finding = next(f for f in payload["findings"] if f["type"] == "sqlalchemy_text_review_required")
    assert finding["sqlalchemy_pattern_key"] == "quoted_identifier_builder"


def test_sqlalchemy_unrelated_unknown_complex_patterns_do_not_collapse(tmp_path: Path) -> None:
    project = tmp_path / "cluster_repo4"
    project.mkdir()
    (project / "a.py").write_text(
        "from sqlalchemy import text\n"
        "def q(parts):\n"
        "    where_sql = ' AND '.join(parts)\n"
        "    return text(f\"SELECT * FROM t WHERE {where_sql}\")\n",
        encoding="utf-8",
    )
    (project / "b.py").write_text(
        "from sqlalchemy import text\n"
        "def _quote_ident(x):\n"
        "    return x\n"
        "def q(table):\n"
        "    return text(f\"SELECT * FROM {_quote_ident(table)}\")\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    sql_findings = [f for f in payload["findings"] if f["type"] == "sqlalchemy_text_review_required"]
    assert len(sql_findings) == 2
    fingerprints = {f["sqlalchemy_pattern_fingerprint"] for f in sql_findings}
    assert len(fingerprints) == 2
    keys = {f["sqlalchemy_pattern_key"] for f in sql_findings}
    assert keys == {"dynamic_where_fragment", "quoted_identifier_builder"}


def test_sqlalchemy_clustering_does_not_change_raw_finding_count(tmp_path: Path) -> None:
    project = tmp_path / "cluster_repo5"
    project.mkdir()
    (project / "a.py").write_text(
        "from sqlalchemy import text\n"
        "def q(x):\n"
        "    return text(f\"SELECT * FROM t WHERE id = {x}\")\n",
        encoding="utf-8",
    )
    payload = _run(SecretsHeuristicScanner(), project)
    raw_count = len(payload["findings"])
    summary_count = int(payload["sqlalchemy_clustering"]["total_sqlalchemy_findings"])
    assert raw_count == summary_count
