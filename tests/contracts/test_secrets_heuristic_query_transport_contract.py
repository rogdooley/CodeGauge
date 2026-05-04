from __future__ import annotations

from codegauge.scanners.secrets_heuristic_scanner import _QUERY_PARAM_HINTS


def test_query_transport_detection_keys_include_required_baseline() -> None:
    required = {
        "challenge_token",
        "public_token",
        "invite_created",
        "created",
        "invite_code",
        "reset_token",
        "api_key",
        "key",
        "session_token",
    }
    assert required.issubset(set(_QUERY_PARAM_HINTS))
