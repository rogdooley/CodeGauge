from __future__ import annotations

import subprocess
from pathlib import Path
from time import perf_counter
from typing import Sequence

from ..services.build_runner import select_build_runner
from .base import Scanner, ScannerCommandResult


class ErrorProneScanner(Scanner):
    scanner_name = "errorprone"
    supported_languages = ["java"]

    def is_available(self) -> bool:
        return True

    def build_command(self, project_path: Path) -> list[str]:
        runner = select_build_runner(project_path)
        if runner is None:
            return ["<build-runner-missing>"]
        tasks = ("test", "verify") if runner.runner_name == "maven" else ("test", "check")
        plan = runner.build_plan(
            project_path,
            tasks=tasks,
            artifact_relative_paths=(),
            extra_args=self.extra_args,
        )
        return plan.command

    def execute(self, project_path: Path, files: Sequence[Path] | None = None) -> ScannerCommandResult:
        _ = files
        runner = select_build_runner(project_path)
        if runner is None:
            return ScannerCommandResult(
                command=[],
                stdout="",
                stderr="",
                success=False,
                duration_ms=0.0,
                error_code="scanner_config_error",
                error=f"no supported Java build runner found for scanner {self.scanner_name}",
            )
        if not runner.is_available(project_path):
            command = self.build_command(project_path)
            return ScannerCommandResult(
                command=command,
                stdout="",
                stderr="",
                success=False,
                duration_ms=0.0,
                error_code="scanner_binary_missing",
                error=f"{runner.runner_name} executable not found",
            )
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
            success = completed.returncode == 0
            return ScannerCommandResult(
                command=command,
                stdout=completed.stdout,
                stderr=completed.stderr,
                success=success,
                duration_ms=duration,
                exit_code=completed.returncode,
                error_code=None if success else "scanner_nonzero_exit",
                error=None if success else f"scanner exited with code {completed.returncode}",
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
                error_code="scanner_timeout",
                error=f"scanner timed out after {self.timeout_seconds} seconds",
            )
