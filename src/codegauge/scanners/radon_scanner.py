from __future__ import annotations

import json
import subprocess
from time import perf_counter
import shutil
from pathlib import Path
from typing import Sequence

from .base import Scanner, ScannerCommandResult


class RadonScanner(Scanner):
    scanner_name = "radon"
    supported_languages = ["python"]

    def is_available(self) -> bool:
        return shutil.which("radon") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["radon", "cc", "-j", str(project_path), *self.extra_args]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files: Sequence[Path]) -> list[str]:
        _ = project_path
        paths = [str(path) for path in files]
        return ["radon", "cc", "-j", *paths, *self.extra_args]

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

        if files is not None:
            cc_command = ["radon", "cc", "-j", *[str(path) for path in files], *self.extra_args]
            mi_command = ["radon", "mi", "-j", *[str(path) for path in files], *self.extra_args]
        else:
            cc_command = ["radon", "cc", "-j", str(project_path), *self.extra_args]
            mi_command = ["radon", "mi", "-j", str(project_path), *self.extra_args]
        start = perf_counter()
        try:
            cc = subprocess.run(
                cc_command,
                cwd=self.work_dir or project_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            if cc.returncode != 0:
                duration = (perf_counter() - start) * 1000
                return ScannerCommandResult(
                    command=cc_command,
                    stdout=cc.stdout,
                    stderr=cc.stderr,
                    success=False,
                    duration_ms=duration,
                    exit_code=cc.returncode,
                    error_code="scanner_nonzero_exit",
                    error=f"scanner exited with code {cc.returncode}",
                )

            mi = subprocess.run(
                mi_command,
                cwd=self.work_dir or project_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            if mi.returncode != 0:
                duration = (perf_counter() - start) * 1000
                return ScannerCommandResult(
                    command=mi_command,
                    stdout=mi.stdout,
                    stderr=mi.stderr,
                    success=False,
                    duration_ms=duration,
                    exit_code=mi.returncode,
                    error_code="scanner_nonzero_exit",
                    error=f"scanner exited with code {mi.returncode}",
                )

            merged = json.dumps({"cc": json.loads(cc.stdout or "{}"), "mi": json.loads(mi.stdout or "{}")})
            duration = (perf_counter() - start) * 1000
            return ScannerCommandResult(
                command=cc_command + ["&&"] + mi_command,
                stdout=merged,
                stderr="\n".join(part for part in [cc.stderr, mi.stderr] if part),
                success=True,
                duration_ms=duration,
                exit_code=0,
            )
        except subprocess.TimeoutExpired as exc:
            duration = (perf_counter() - start) * 1000
            stdout = (exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout) or ""
            stderr = (exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr) or ""
            return ScannerCommandResult(
                command=cc_command,
                stdout=stdout,
                stderr=stderr,
                success=False,
                duration_ms=duration,
                error_code="scanner_timeout",
                error=f"scanner timed out after {self.timeout_seconds} seconds",
            )
        except FileNotFoundError:
            duration = (perf_counter() - start) * 1000
            return ScannerCommandResult(
                command=cc_command,
                stdout="",
                stderr="",
                success=False,
                duration_ms=duration,
                error_code="scanner_binary_missing",
                error="scanner binary not found: radon",
            )
        except ValueError as exc:
            duration = (perf_counter() - start) * 1000
            return ScannerCommandResult(
                command=cc_command,
                stdout="",
                stderr=str(exc),
                success=False,
                duration_ms=duration,
                error_code="scanner_output_invalid",
                error=f"scanner produced invalid JSON: {exc}",
            )
