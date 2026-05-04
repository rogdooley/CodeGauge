from __future__ import annotations

import json
from pathlib import Path

from codegauge.parsers.git_history_secrets_parser import GitHistorySecretsParser
from codegauge.parsers.gitleaks_parser import GitleaksParser
from codegauge.parsers.secrets_heuristic_parser import SecretsHeuristicParser
from codegauge.parsers.trufflehog_parser import TruffleHogParser


def test_gitleaks_parser_normalizes_secret_category() -> None:
    parser = GitleaksParser()
    stdout = json.dumps(
        [
            {
                "File": "src/app.py",
                "Description": "AWS token",
                "StartLine": 12,
                "RuleID": "generic-api-key",
                "Secret": "abc",
            }
        ]
    )
    findings = parser.parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].rule_id == "real_secret_exposure"
    assert findings[0].raw_payload["secret_real"] is True
    assert findings[0].raw_payload["confidence"] == "verified"


def test_trufflehog_parser_handles_jsonl() -> None:
    parser = TruffleHogParser()
    line = json.dumps(
        {
            "DetectorName": "PrivateKey",
            "SourceMetadata": {"Data": {"Filesystem": {"file": "keys/id_rsa"}}},
            "Raw": "SECRET",
        }
    )
    findings = parser.parse(line, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].rule_id == "probable_secret_exposure"
    assert findings[0].raw_payload["verified"] is False
    assert findings[0].raw_payload["confidence"] == "probable"


def test_trufflehog_parser_verified_maps_to_real_secret_exposure() -> None:
    parser = TruffleHogParser()
    line = json.dumps(
        {
            "Verified": True,
            "DetectorName": "GithubToken",
            "SourceMetadata": {"Data": {"Filesystem": {"file": "src/app.py"}}},
        }
    )
    findings = parser.parse(line, "", Path.cwd())
    assert findings[0].rule_id == "real_secret_exposure"
    assert findings[0].raw_payload["verified"] is True
    assert findings[0].raw_payload["confidence"] == "verified"


def test_secrets_heuristic_parser_maps_categories() -> None:
    parser = SecretsHeuristicParser()
    stdout = json.dumps({"findings": [{"type": "sensitive_path", "file": ".env", "message": "risk", "confidence": "weak"}]})
    findings = parser.parse(stdout, "", Path.cwd())
    assert findings[0].rule_id == "weak_secret_management"
    assert findings[0].raw_payload["secret_real"] is False


def test_secrets_heuristic_parser_maps_probable_without_real_secret() -> None:
    parser = SecretsHeuristicParser()
    stdout = json.dumps(
        {
            "findings": [
                {
                    "type": "probable_secret_exposure",
                    "file": "src/settings.py",
                    "line": 4,
                    "message": "Potential secret assignment",
                    "confidence": "probable",
                }
            ]
        }
    )
    findings = parser.parse(stdout, "", Path.cwd())
    assert findings[0].rule_id == "probable_secret_exposure"
    assert findings[0].raw_payload["confidence"] == "probable"
    assert findings[0].raw_payload["secret_real"] is False


def test_secrets_heuristic_parser_returns_scalar_metrics_metadata() -> None:
    parser = SecretsHeuristicParser()
    stdout = json.dumps(
        {
            "findings": [],
            "scalar_metrics": {
                "secrets_candidates_seen": 10,
                "secrets_allowlisted": 4,
                "secrets_noise_dropped": 5,
                "secrets_probable": 1,
                "secrets_weak": 0,
                "secrets_suppression_rate_percent": 90.0,
            },
        }
    )
    metadata = parser.parse_metadata(stdout, "", Path.cwd())
    assert metadata["scalar_metrics"]["secrets_candidates_seen"] == 10
    assert metadata["scalar_metrics"]["secrets_suppression_rate_percent"] == 90.0


def test_git_history_parser_maps_to_historical_category() -> None:
    parser = GitHistorySecretsParser()
    stdout = json.dumps(
        {
            "findings": [
                {
                    "type": "historical_secret_exposure",
                    "file": "src/app.py",
                    "message": "found AKIA1234567890ABCDEF",
                    "commit": "abc",
                }
            ]
        }
    )
    findings = parser.parse(stdout, "", Path.cwd())
    assert findings[0].rule_id == "historical_secret_exposure"


def test_git_history_parser_ignores_generic_secret_words_without_credential_value() -> None:
    parser = GitHistorySecretsParser()
    stdout = json.dumps(
        {
            "findings": [
                {
                    "type": "historical_secret_exposure",
                    "file": "src/app.py",
                    "message": "found token/password/secret marker",
                    "line": "token password secret",
                }
            ]
        }
    )
    findings = parser.parse(stdout, "", Path.cwd())
    assert findings == []


def test_secrets_heuristic_parser_maps_url_bearer_transport_rule() -> None:
    parser = SecretsHeuristicParser()
    stdout = json.dumps(
        {
            "findings": [
                {
                    "type": "intentional_bearer_issuance_url_transport",
                    "file": "src/app.py",
                    "line": 10,
                    "message": "Bearer material in URL query",
                    "confidence": "probable",
                    "severity": "high",
                    "subtype": "invite_capability_code",
                    "token_variable": "invite_code",
                    "issuer_symbol": "create_invite",
                    "transport_kind": "query",
                    "severity_reason": "high_risk_token_characteristics_or_url_observability",
                }
            ]
        }
    )
    findings = parser.parse(stdout, "", Path.cwd())
    assert findings[0].rule_id == "intentional_bearer_issuance_url_transport"
    assert findings[0].severity.value == "high"
    assert findings[0].raw_payload["subtype"] == "invite_capability_code"
