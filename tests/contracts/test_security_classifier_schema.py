from __future__ import annotations

import json
from pathlib import Path

from codegauge.services.security_classifier import SecurityFindingClassifier


def test_security_classifier_schema_matches_contract_strictly() -> None:
    schema_path = Path("schemas/security-classification.schema.json")
    schema_payload = json.loads(schema_path.read_text(encoding="utf-8"))
    contract = SecurityFindingClassifier.contract()
    expected = {
        "classifier_name": contract["classifier"]["name"],
        "classifier_version": contract["classifier"]["version"],
        "reason_codes": contract["reason_codes"],
        "security_classes": contract["security_classes"],
        "security_contexts": contract["security_contexts"],
    }
    assert schema_payload == expected
