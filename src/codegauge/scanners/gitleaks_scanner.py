from __future__ import annotations

import shutil
import tempfile
import subprocess
from time import perf_counter
from pathlib import Path
from typing import Sequence

from ..constants import ScannerErrorCode
from .base import Scanner
from .base import ScannerCommandResult


class GitleaksScanner(Scanner):
    scanner_name = "gitleaks"
    supported_languages = ["general"]

    def is_available(self) -> bool:
        return shutil.which("gitleaks") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return [
            "gitleaks",
            "detect",
            "--source",
            str(project_path),
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--no-git",
            *self.extra_args,
        ]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files: Sequence[Path]) -> list[str]:
        del files
        return self.build_command(project_path)

    def execute(self, project_path: Path, files: Sequence[Path] | None = None) -> ScannerCommandResult:
        if not files:
            return super().execute(project_path, files=None)
        start = perf_counter()
        with tempfile.TemporaryDirectory(prefix="codegauge-secrets-gitleaks-") as temp_dir:
            scope_root = Path(temp_dir)
            for file_path in files:
                rel = file_path.resolve().relative_to(project_path.resolve())
                dest = scope_root / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file_path, dest)
            command = self.build_command(scope_root)
            try:
                completed = subprocess.run(
                    command,
                    cwd=self.work_dir or scope_root,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                duration = (perf_counter() - start) * 1000
                return ScannerCommandResult(
                    command=command,
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                    success=completed.returncode == 0,
                    duration_ms=duration,
                    exit_code=completed.returncode,
                    error_code=None if completed.returncode == 0 else ScannerErrorCode.nonzero_exit,
                    error=None if completed.returncode == 0 else f"scanner exited with code {completed.returncode}",
                )
            except subprocess.TimeoutExpired as exc:
                duration = (perf_counter() - start) * 1000
                stdout = (exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout) or ""
                stderr = (exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr) or ""
                return ScannerCommandResult(
                    command=command,
                    stdout=stdout,
                    stderr=stderr,
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
                    error="scanner binary not found: gitleaks",
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
