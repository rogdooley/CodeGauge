from __future__ import annotations

import json
import subprocess
from time import perf_counter
import shutil
from pathlib import Path

from .base import Scanner, ScannerCommandResult


class RadonScanner(Scanner):
    scanner_name = "radon"
    supported_languages = ["python"]

    def is_available(self) -> bool:
        return shutil.which("radon") is not None

    def build_command(self, project_path: Path) -> list[str]:
        return ["radon", "cc", "-j", str(project_path), *self.extra_args]

    def execute(self, project_path: Path) -> ScannerCommandResult:
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
            return ScannerCommandResult(
                command=cc_command,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
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
