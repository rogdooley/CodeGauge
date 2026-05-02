from __future__ import annotations

from pathlib import Path
from typing import Sequence

from ..domain.models import Finding
from ..domain.models import Severity
from .base import ScannerParser
from .formats.json_parser import parse_json_document, require_list, require_object, require_string
from .secrets_parser_common import _secret_finding


class GitleaksParser(ScannerParser):
    parser_name = "gitleaks_parser"
    supported_scanners = ("gitleaks",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        del stderr
        if not stdout.strip():
            return []
        payload = parse_json_document(stdout, scanner_name="gitleaks")
        entries = require_list(payload, context="gitleaks findings")
        findings = []
        for item in entries:
            entry = require_object(item, context="gitleaks finding")
            file_value = require_string(entry.get("File") or entry.get("file") or "", context="gitleaks file")
            desc = str(entry.get("Description") or entry.get("description") or "Secret detected")
            line = entry.get("StartLine") or entry.get("line")
            if not isinstance(line, int):
                line = None
            rule = str(entry.get("RuleID") or entry.get("rule") or "").upper()
            secret_category = "real_secret_exposure"
            sev = Severity.high
            if "PRIVATE" in rule and "KEY" in rule:
                secret_category = "private_key_material"
                sev = Severity.critical
            elif "CERT" in rule:
                secret_category = "certificate_material"
            findings.append(
                _secret_finding(
                    tool="gitleaks",
                    rule_id=secret_category,
                    file_value=file_value,
                    message=desc,
                    project_path=project_path,
                    line=line,
                    severity=sev,
                    confidence=0.98,
                    tags=["real_secret", "secrets_profile", "verified"],
                    raw_payload={**entry, "secret_real": True, "confidence": "verified", "verified": True},
                )
            )
        return findings
