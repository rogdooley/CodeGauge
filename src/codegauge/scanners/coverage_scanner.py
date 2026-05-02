from __future__ import annotations

import shutil
import subprocess
from time import perf_counter
from pathlib import Path
from typing import Sequence

from ..constants import ScannerErrorCode
from .base import Scanner, ScannerCommandResult


class CoverageScanner(Scanner):
    scanner_name = "coverage"
    supported_languages = ["python"]

    def is_available(self) -> bool:
        return shutil.which("coverage") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["coverage", "json", "-o", "-", *self.extra_args]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files: Sequence[Path]) -> list[str]:
        _ = project_path
        _ = files
        return ["coverage", "json", "-o", "-", *self.extra_args]

    def execute(self, project_path: Path, files: Sequence[Path] | None = None) -> ScannerCommandResult:
        _ = files
        command = self.build_command(project_path)
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
                error="scanner binary not found: coverage",
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
        stderr = completed.stderr or ""
        if completed.returncode != 0:
            lowered = stderr.lower()
            stdout_lowered = (completed.stdout or "").lower()
            if "no data to report" in lowered or "no data was collected" in lowered or "no such file" in lowered:
                empty_payload = '{"totals": {"percent_covered": 0.0}}'
                return ScannerCommandResult(
                    command=command,
                    stdout=empty_payload,
                    stderr=stderr,
                    success=True,
                    duration_ms=duration,
                    exit_code=completed.returncode,
                    metadata={"coverage_missing_data": True},
                )
            if "no data to report" in stdout_lowered or "no data was collected" in stdout_lowered:
                empty_payload = '{"totals": {"percent_covered": 0.0}}'
                return ScannerCommandResult(
                    command=command,
                    stdout=empty_payload,
                    stderr=stderr,
                    success=True,
                    duration_ms=duration,
                    exit_code=completed.returncode,
                    metadata={"coverage_missing_data": True},
                )
            return ScannerCommandResult(
                command=command,
                stdout=completed.stdout,
                stderr=stderr,
                success=False,
                duration_ms=duration,
                exit_code=completed.returncode,
                error_code=ScannerErrorCode.nonzero_exit,
                error=f"scanner exited with code {completed.returncode}",
            )

        return ScannerCommandResult(
            command=command,
            stdout=completed.stdout,
            stderr=stderr,
            success=True,
            duration_ms=duration,
            exit_code=completed.returncode,
        )
