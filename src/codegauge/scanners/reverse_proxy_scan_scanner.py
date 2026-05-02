from __future__ import annotations

import sys
from pathlib import Path

from .base import Scanner


class ReverseProxyScanScanner(Scanner):
    scanner_name = "reverse_proxy_scan"
    supported_languages = ["general"]

    def is_available(self) -> bool:
        return True

    def build_command(self, project_path: Path) -> list[str]:
        script = r"""
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
files = []
files.extend(root.rglob("*traefik*.yml"))
files.extend(root.rglob("*traefik*.yaml"))
files.extend(root.rglob("nginx.conf"))
files.extend(root.rglob("*.nginx.conf"))
files.extend(root.rglob("httpd.conf"))
files.extend(root.rglob("apache2.conf"))
findings = []
for path in files[:500]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    rel = path.relative_to(root).as_posix()
    if re.search(r"(?i)ssl_protocols\s+TLSv1\b", text):
        findings.append({"rule_id": "INF.PROXY.LEGACY_TLS", "file": rel, "line": 1, "message": "Legacy TLS protocol enabled", "severity": "high"})
    if re.search(r"(?i)server_tokens\s+on\b", text):
        findings.append({"rule_id": "INF.PROXY.SERVER_TOKENS", "file": rel, "line": 1, "message": "Server version disclosure enabled", "severity": "low"})
    if re.search(r"(?i)insecureSkipVerify\s*:\s*true\b", text):
        findings.append({"rule_id": "INF.PROXY.INSECURE_UPSTREAM_TLS", "file": rel, "line": 1, "message": "Insecure upstream TLS verify disabled", "severity": "high"})
print(json.dumps({"findings": findings, "scalar_metrics": {"proxy_config_count": len(files)}}))
"""
        return [sys.executable, "-c", script, str(project_path)]
