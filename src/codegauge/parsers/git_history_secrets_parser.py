from __future__ import annotations

import re
from pathlib import Path
from typing import Sequence

from ..domain.models import Finding
from ..domain.models import Severity
from .base import ScannerParser
from .formats.json_parser import parse_json_document, require_list, require_object, require_string
from .secrets_parser_common import _secret_finding

_CREDENTIAL_LIKE_VALUE_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|eyJ[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+|-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)"
)


def _has_credential_like_value(entry: dict[str, object]) -> bool:
    for key in ("secret", "value", "match", "line", "content", "raw", "snippet", "message"):
        value = entry.get(key)
        if isinstance(value, str) and _CREDENTIAL_LIKE_VALUE_RE.search(value):
            return True
    return False


class GitHistorySecretsParser(ScannerParser):
    parser_name = "git_history_secrets_parser"
    supported_scanners = ("git_history_secrets",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        del stderr
        if not stdout.strip():
            return []
        payload = parse_json_document(stdout, scanner_name="git_history_secrets")
        root = require_object(payload, context="git history secrets payload")
        rows = require_list(root.get("findings") or [], context="git history findings")
        findings = []
        for item in rows:
            entry = require_object(item, context="git history finding")
            if not _has_credential_like_value(entry):
                continue
            file_value = require_string(entry.get("file"), context="git history finding file")
            finding_type = require_string(entry.get("type"), context="git history type")
            message = require_string(entry.get("message") or "Historical secret detected", context="git history message")
            if finding_type == "historical_private_key_material":
                category = "historical_secret_exposure"
                severity = Severity.critical
            else:
                category = "historical_secret_exposure"
                severity = Severity.high
            findings.append(
                _secret_finding(
                    tool="git_history_secrets",
                    rule_id=category,
                    file_value=file_value,
                    message=message,
                    project_path=project_path,
                    severity=severity,
                    tags=["history", "real_secret", "secrets_profile"],
                    raw_payload={**entry, "secret_real": True, "historical": True},
                )
            )
        return findings
