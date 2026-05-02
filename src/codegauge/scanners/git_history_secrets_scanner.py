from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from time import perf_counter

from .base import Scanner, ScannerCommandResult

_HISTORY_SECRET_RE = re.compile(
    r"(?i)(password|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*['\"]?([^\s'\"#]{8,})"
)
_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")


class GitHistorySecretsScanner(Scanner):
    scanner_name = "git_history_secrets"
    supported_languages = ["general"]

    def is_available(self) -> bool:
        return shutil.which("git") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["git", "-C", str(project_path), "log", "-p", "--all", "--", "."]

    def execute(self, project_path: Path, files=None) -> ScannerCommandResult:
        del files
        command = self.build_command(project_path)
        start = perf_counter()
        try:
            completed = subprocess.run(
                command,
                cwd=project_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except Exception as exc:
            duration = (perf_counter() - start) * 1000
            return ScannerCommandResult(command=command, stdout="", stderr="", success=False, duration_ms=duration, error=str(exc))

        findings: list[dict[str, object]] = []
        current_file = ""
        current_commit = ""
        for line in completed.stdout.splitlines():
            if line.startswith("commit "):
                current_commit = line.split(" ", 1)[1].strip()
                continue
            if line.startswith("+++ b/"):
                current_file = line.removeprefix("+++ b/").strip()
                continue
            if not line.startswith("+") or line.startswith("+++"):
                continue
            content = line[1:]
            if _KEY_RE.search(content):
                findings.append(
                    {
                        "type": "historical_private_key_material",
                        "file": current_file or "<unknown>",
                        "message": "Private key material appears in git history.",
                        "commit": current_commit,
                    }
                )
                continue
            match = _HISTORY_SECRET_RE.search(content)
            if match is not None:
                findings.append(
                    {
                        "type": "historical_secret_exposure",
                        "file": current_file or "<unknown>",
                        "message": f"Potential secret assignment in git history: {match.group(1)}.",
                        "commit": current_commit,
                        "secret_value": match.group(2),
                    }
                )
        duration = (perf_counter() - start) * 1000
        success = completed.returncode == 0
        return ScannerCommandResult(
            command=command,
            stdout=json.dumps({"findings": findings}, ensure_ascii=True),
            stderr=completed.stderr,
            success=success,
            duration_ms=duration,
            exit_code=completed.returncode,
            error=None if success else f"scanner exited with code {completed.returncode}",
        )
