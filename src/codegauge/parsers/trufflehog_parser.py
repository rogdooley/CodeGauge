from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from ..domain.models import Finding
from ..domain.models import Severity
from .base import ScannerParser
from .formats.json_parser import require_object
from .secrets_parser_common import _secret_finding


class TruffleHogParser(ScannerParser):
    parser_name = "trufflehog_parser"
    supported_scanners = ("trufflehog",)

    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        del stderr
        if not stdout.strip():
            return []
        findings = []
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            entry = require_object(json.loads(line), context="trufflehog finding")
            source_meta = entry.get("SourceMetadata") if isinstance(entry.get("SourceMetadata"), dict) else {}
            data = source_meta.get("Data") if isinstance(source_meta.get("Data"), dict) else {}
            fs = data.get("Filesystem") if isinstance(data.get("Filesystem"), dict) else {}
            file_value = str(fs.get("file") or fs.get("path") or "unknown")
            detector = str(entry.get("DetectorName") or entry.get("DetectorType") or "trufflehog")
            verified = bool(entry.get("Verified", False))
            secret_category = "real_secret_exposure" if verified else "probable_secret_exposure"
            sev = Severity.high if verified else Severity.medium
            detector_upper = detector.upper()
            if verified:
                if "PRIVATE" in detector_upper and "KEY" in detector_upper:
                    secret_category = "private_key_material"
                    sev = Severity.critical
                elif "CERT" in detector_upper:
                    secret_category = "certificate_material"
                    sev = Severity.high
            findings.append(
                _secret_finding(
                    tool="trufflehog",
                    rule_id=secret_category,
                    file_value=file_value,
                    message=f"{'Verified' if verified else 'Unverified'} credential detector hit: {detector}",
                    project_path=project_path,
                    severity=sev,
                    confidence=(0.98 if verified else 0.7),
                    tags=(["real_secret", "verified"] if verified else ["unverified", "probable"]) + ["secrets_profile"],
                    raw_payload={
                        **entry,
                        "verified": verified,
                        "confidence": "verified" if verified else "probable",
                        "secret_real": verified,
                    },
                )
            )
        return findings
