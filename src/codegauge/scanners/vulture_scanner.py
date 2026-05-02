from __future__ import annotations

import json
import re
import shutil
import subprocess
from time import perf_counter
from pathlib import Path
from typing import Sequence

from ..constants import ScannerErrorCode
from .base import Scanner, ScannerCommandResult


class VultureScanner(Scanner):
    scanner_name = "vulture"
    supported_languages = ["python"]

    _OUTPUT_LINE = re.compile(
        r"^(?P<filename>.+?):(?P<line>\d+):\s+unused\s+"
        r"(?P<kind>[A-Za-z_][A-Za-z0-9_ ]*?)\s+['\"](?P<name>.+?)['\"]\s+"
        r"\((?P<confidence>\d+)% confidence\)$"
    )

    def is_available(self) -> bool:
        return shutil.which("vulture") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["vulture", str(project_path), *self.extra_args]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files: Sequence[Path]) -> list[str]:
        _ = project_path
        return ["vulture", *[str(path) for path in files], *self.extra_args]

    def _to_json_payload(self, stdout: str) -> str:
        stripped = stdout.strip()
        if stripped.startswith("["):
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, list):
                return json.dumps(payload)
        entries: list[dict[str, object]] = []
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            match = self._OUTPUT_LINE.match(line)
            if match is None:
                continue
            entries.append(
                {
                    "filename": match.group("filename"),
                    "first_line": int(match.group("line")),
                    "name": match.group("name"),
                    "type": match.group("kind"),
                    "confidence": int(match.group("confidence")),
                }
            )
        return json.dumps(entries)

    def execute(self, project_path: Path, files: Sequence[Path] | None = None) -> ScannerCommandResult:
        if files is not None and not self.supports_explicit_file_list():
            return ScannerCommandResult(
                command=[],
                stdout="",
                stderr="",
                success=False,
                duration_ms=0.0,
                error_code="scanner_contract_violation",
                error=f"scanner does not support explicit file-list execution: {self.scanner_name}",
            )
        command = self.build_command_for_files(project_path, files) if files is not None else self.build_command(project_path)
        start = perf_counter()
        try:
            completed = subprocess.run(
                command,
                cwd=self.work_dir or project_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            duration = (perf_counter() - start) * 1000
            return ScannerCommandResult(
                command=command,
                stdout=(exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout) or "",
                stderr=(exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr) or "",
                success=False,
                duration_ms=duration,
                error_code=ScannerErrorCode.timeout,
                error=f"scanner timed out after {self.timeout_seconds} seconds",
            )
        except FileNotFoundError:
            duration = (perf_counter() - start) * 1000
            return ScannerCommandResult(
                command=command,
                stdout="",
                stderr="",
                success=False,
                duration_ms=duration,
                error_code=ScannerErrorCode.binary_missing,
                error="scanner binary not found: vulture",
            )
        except OSError as exc:
            duration = (perf_counter() - start) * 1000
            return ScannerCommandResult(
                command=command,
                stdout="",
                stderr="",
                success=False,
                duration_ms=duration,
                error_code=ScannerErrorCode.config_error,
                error=f"scanner execution failed: {exc}",
            )

        duration = (perf_counter() - start) * 1000
        parsed_stdout = self._to_json_payload(completed.stdout or "")
        if completed.returncode != 0:
            if parsed_stdout != "[]":
                return ScannerCommandResult(
                    command=command,
                    stdout=parsed_stdout,
                    stderr=completed.stderr,
                    success=True,
                    duration_ms=duration,
                    exit_code=completed.returncode,
                )
            if not (completed.stdout or "").strip() and not (completed.stderr or "").strip():
                return ScannerCommandResult(
                    command=command,
                    stdout="[]",
                    stderr="",
                    success=True,
                    duration_ms=duration,
                    exit_code=completed.returncode,
                    metadata={"vulture_empty_result": True},
                )
            stderr_lower = (completed.stderr or "").lower()
            stdout_lower = (completed.stdout or "").lower()
            if "no python source" in stderr_lower or "invalid path" in stderr_lower or "no python source" in stdout_lower:
                return ScannerCommandResult(
                    command=command,
                    stdout="[]",
                    stderr=completed.stderr,
                    success=True,
                    duration_ms=duration,
                    exit_code=completed.returncode,
                    metadata={"vulture_empty_result": True},
                )
            return ScannerCommandResult(
                command=command,
                stdout=completed.stdout,
                stderr=completed.stderr,
                success=False,
                duration_ms=duration,
                exit_code=completed.returncode,
                error_code=ScannerErrorCode.nonzero_exit,
                error=f"scanner exited with code {completed.returncode}",
            )

        return ScannerCommandResult(
            command=command,
            stdout=parsed_stdout,
            stderr=completed.stderr,
            success=True,
            duration_ms=duration,
            exit_code=completed.returncode,
        )
