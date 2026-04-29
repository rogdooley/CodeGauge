from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Any, Mapping, Sequence

from ..constants import ScannerErrorCode


@dataclass
class ScannerCommandResult:
    command: list[str]
    stdout: str
    stderr: str
    success: bool
    duration_ms: float
    exit_code: int | None = None
    error_code: str | None = None
    error: str | None = None
    metadata: Mapping[str, Any] | None = None


class Scanner(ABC):
    scanner_name: str
    supported_languages: Sequence[str]
    timeout_seconds: int = 120

    def __init__(
        self,
        work_dir: Path | None = None,
        timeout_seconds: int | None = None,
        extra_args: Sequence[str] | None = None,
    ) -> None:
        self.work_dir = work_dir
        if timeout_seconds is not None:
            self.timeout_seconds = timeout_seconds
        self.extra_args = list(extra_args or [])

    @abstractmethod
    def is_available(self) -> bool:
        ...

    @abstractmethod
    def build_command(self, project_path: Path) -> list[str]:
        ...

    def supports_explicit_file_list(self) -> bool:
        return False

    def build_command_for_files(self, project_path: Path, files: Sequence[Path]) -> list[str]:
        raise NotImplementedError(f"{self.scanner_name} does not implement explicit file-list execution")

    def execute(self, project_path: Path, files: Sequence[Path] | None = None) -> ScannerCommandResult:
        if files is not None:
            if not self.supports_explicit_file_list():
                return ScannerCommandResult(
                    command=[],
                    stdout="",
                    stderr="",
                    success=False,
                    duration_ms=0.0,
                    error_code=ScannerErrorCode.contract_violation,
                    error=f"scanner does not support explicit file-list execution: {self.scanner_name}",
                )
            command = self.build_command_for_files(project_path, files)
        else:
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
            return ScannerCommandResult(
                command=command,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                success=False,
                duration_ms=duration,
                error_code=ScannerErrorCode.timeout,
                error=f"scanner timed out after {self.timeout_seconds} seconds",
            )
        except FileNotFoundError:
            duration = (perf_counter() - start) * 1000
            binary = command[0] if command else self.scanner_name
            return ScannerCommandResult(
                command=command,
                stdout="",
                stderr="",
                success=False,
                duration_ms=duration,
                error_code=ScannerErrorCode.binary_missing,
                error=f"scanner binary not found: {binary}",
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
