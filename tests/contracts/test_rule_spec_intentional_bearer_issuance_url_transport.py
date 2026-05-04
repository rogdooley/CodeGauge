from __future__ import annotations

import json
from pathlib import Path


def test_intentional_bearer_rule_spec_contract_is_stable() -> None:
    spec_path = Path("Documentation/rule_specs/intentional_bearer_issuance_url_transport.json")
    payload = json.loads(spec_path.read_text(encoding="utf-8"))

    assert payload["schema_version"] == "1.0.0"
    assert payload["rule_id"] == "intentional_bearer_issuance_url_transport"
    assert payload["category"] == "security"
    assert payload["default_severity"] == "medium"

    assert payload["subtypes"] == [
        "public_access_token",
        "invite_capability_code",
        "reset_token",
        "api_key",
        "session_token",
        "unknown_capability_token",
    ]

    assert payload["severity_escalation_conditions"] == [
        "token_or_code_long_lived",
        "token_or_code_multi_use",
        "token_or_code_non_revocable",
        "token_or_code_grants_privileged_capability",
        "full_url_logging_enabled",
        "third_party_telemetry_captures_urls",
    ]
    assert payload["severity_downgrade_to_low_when_all_true"] == [
        "single_use",
        "short_ttl",
        "revocable",
        "not_logged_in_app_proxy_or_access_logs",
        "not_exposed_to_telemetry",
    ]
    assert payload["emitted_metadata"] == [
        "subtype",
        "token_variable",
        "issuer_symbol",
        "transport_kind",
        "severity_reason",
        "confidence",
    ]

    remediation = payload.get("remediation")
    assert isinstance(remediation, list)
    assert any("flash/session PRG" in item for item in remediation)
    assert any("XHR create" in item for item in remediation)

    examples = payload.get("examples")
    assert isinstance(examples, list)
    assert any(example.get("expected", {}).get("finding") is True for example in examples)
    assert any(example.get("expected", {}).get("finding") is False for example in examples)


def test_bearer_token_in_url_path_placeholder_spec_contract() -> None:
    spec_path = Path("Documentation/rule_specs/bearer_token_in_url_path.json")
    payload = json.loads(spec_path.read_text(encoding="utf-8"))

    assert payload["schema_version"] == "1.0.0"
    assert payload["rule_id"] == "bearer_token_in_url_path"
    assert payload["category"] == "security"
    assert payload["implemented"] is False
    assert payload["default_severity"] == "low"
    assert payload["severity_range"] == ["low", "medium"]
    assert payload["severity_escalation_conditions"] == [
        "token_or_code_long_lived",
        "token_or_code_multi_use",
        "token_or_code_non_revocable",
        "token_or_code_grants_privileged_capability",
    ]
