from __future__ import annotations

import json
from pathlib import Path

from ..services.security_classifier import SecurityFindingClassifier


def generate_security_classification_contract(path: Path) -> None:
    contract = SecurityFindingClassifier.contract()
    payload = {
        "classifier_name": contract["classifier"]["name"],
        "classifier_version": contract["classifier"]["version"],
        "reason_codes": contract["reason_codes"],
        "security_classes": contract["security_classes"],
        "security_contexts": contract["security_contexts"],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def main() -> None:
    generate_security_classification_contract(Path("schemas/security-classification.schema.json"))


if __name__ == "__main__":
    main()

