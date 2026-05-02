from __future__ import annotations

import subprocess
from time import perf_counter
from pathlib import Path
from typing import Sequence

from ..constants import ScannerErrorCode
from .base import Scanner, ScannerCommandResult


import shutil


class PyrightScanner(Scanner):
    scanner_name = "pyright"
    supported_languages = ["python", "typescript", "javascript"]

    def is_available(self) -> bool:
        return shutil.which("pyright") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["pyright", str(project_path), "--outputjson", *self.extra_args]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files: Sequence[Path]) -> list[str]:
        _ = project_path
        return ["pyright", "--outputjson", *[str(path) for path in files], *self.extra_args]

    def execute(self, project_path: Path, files: Sequence[Path] | None = None) -> ScannerCommandResult:
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
                error="scanner binary not found: pyright",
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
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        if completed.returncode in {0, 1} and stdout.strip():
            return ScannerCommandResult(
                command=command,
                stdout=stdout,
                stderr=stderr,
                success=True,
                duration_ms=duration,
                exit_code=completed.returncode,
            )
        if completed.returncode != 0:
            return ScannerCommandResult(
                command=command,
                stdout=stdout,
                stderr=stderr,
                success=False,
                duration_ms=duration,
                exit_code=completed.returncode,
                error_code=ScannerErrorCode.nonzero_exit,
                error=f"scanner exited with code {completed.returncode}",
            )
        return ScannerCommandResult(
            command=command,
            stdout=stdout,
            stderr=stderr,
            success=True,
            duration_ms=duration,
            exit_code=completed.returncode,
        )
