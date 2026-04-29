from __future__ import annotations

import subprocess
import json
from abc import abstractmethod
from pathlib import Path
from time import perf_counter
from typing import Sequence

from ..services.build_runner import BuildRunner, select_build_runner
from ..storage import JavaBuildCacheService
from ..paths import java_cache_root_for_project
from .base import Scanner, ScannerCommandResult


class JavaBuildArtifactScanner(Scanner):
    supported_languages = ["java"]

    @property
    @abstractmethod
    def maven_tasks(self) -> Sequence[str]:
        ...

    @property
    @abstractmethod
    def gradle_tasks(self) -> Sequence[str]:
        ...

    @property
    @abstractmethod
    def maven_artifact_paths(self) -> Sequence[str]:
        ...

    @property
    @abstractmethod
    def gradle_artifact_paths(self) -> Sequence[str]:
        ...

    def is_available(self) -> bool:
        # Availability is project-dependent (wrapper scripts are local to project).
        return True

    def build_command(self, project_path: Path) -> list[str]:
        runner = select_build_runner(project_path)
        if runner is None:
            return ["<build-runner-missing>"]
        plan = runner.build_plan(
            project_path,
            tasks=self._tasks_for_runner(runner),
            artifact_relative_paths=self._artifacts_for_runner(runner),
            extra_args=self.extra_args,
        )
        return plan.command

    def execute(self, project_path: Path) -> ScannerCommandResult:
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
            plan = runner.build_plan(
                project_path,
                tasks=self._tasks_for_runner(runner),
                artifact_relative_paths=self._artifacts_for_runner(runner),
                extra_args=self.extra_args,
            )
            return ScannerCommandResult(
                command=plan.command,
                stdout="",
                stderr="",
                success=False,
                duration_ms=0.0,
                error_code="scanner_binary_missing",
                error=f"{runner.runner_name} executable not found",
            )

        plan = runner.build_plan(
            project_path,
            tasks=self._tasks_for_runner(runner),
            artifact_relative_paths=self._artifacts_for_runner(runner),
            extra_args=self.extra_args,
        )
        state_root = self.state_root.resolve() if isinstance(self.state_root, Path) else (project_path / ".scan-cache").resolve()
        cache_service = JavaBuildCacheService(
            project_path,
            cache_root=java_cache_root_for_project(state_root, project_path),
        )
        modules = cache_service.discover_modules()
        cache_hits = 0
        cache_misses = 0
        collected_artifact_contents: list[str] = []
        module_updates: list[dict[str, str]] = []
        last_cache_update: str | None = None
        miss_reason_counts: dict[str, int] = {}

        for module in modules:
            module_plan = runner.build_plan(
                module.module_path,
                tasks=self._tasks_for_runner(runner),
                artifact_relative_paths=self._artifacts_for_runner(runner),
                extra_args=self.extra_args,
            )
            cache_key, input_hashes = cache_service.compute_cache_key(module, self.scanner_name)
            reused, miss_reasons, previous_manifest = cache_service.try_reuse(
                module=module,
                tool=self.scanner_name,
                cache_key=cache_key,
                input_hashes=input_hashes,
            )
            if reused:
                cache_hits += 1
                module_updates.append({"module_name": module.module_name, "status": "hit", "miss_reasons": []})
                collected_artifact_contents.extend(path.read_text(encoding="utf-8", errors="ignore") for path in reused)
                manifest = cache_service.save_manifest(
                    module=module,
                    tool=self.scanner_name,
                    cache_key=cache_key,
                    artifact_paths=reused,
                    input_hashes=input_hashes,
                    status="hit",
                    reasons=[],
                    previous_cache_key=previous_manifest.cache_key if previous_manifest else None,
                    previous_manifest=previous_manifest,
                )
                if manifest and manifest.created_at:
                    last_cache_update = manifest.created_at
                continue

            cache_misses += 1
            module_updates.append({"module_name": module.module_name, "status": "miss", "miss_reasons": miss_reasons})
            for reason in miss_reasons:
                miss_reason_counts[reason] = miss_reason_counts.get(reason, 0) + 1
            start = perf_counter()
            try:
                completed = subprocess.run(
                    module_plan.command,
                    cwd=self.work_dir or module.module_path,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                duration = (perf_counter() - start) * 1000
                return ScannerCommandResult(
                    command=module_plan.command,
                    stdout=exc.stdout or "",
                    stderr=exc.stderr or "",
                    success=False,
                    duration_ms=duration,
                    error_code="scanner_timeout",
                    error=f"scanner timed out after {self.timeout_seconds} seconds",
                    metadata={
                        "cache": {
                            "tool": self.scanner_name,
                            "cached_modules": len(modules),
                            "cache_hits": cache_hits,
                            "cache_misses": cache_misses,
                            "module_results": module_updates,
                        }
                    },
                )
            except FileNotFoundError:
                duration = (perf_counter() - start) * 1000
                return ScannerCommandResult(
                    command=module_plan.command,
                    stdout="",
                    stderr="",
                    success=False,
                    duration_ms=duration,
                    error_code="scanner_binary_missing",
                    error=f"scanner binary not found: {module_plan.command[0] if module_plan.command else self.scanner_name}",
                )
            except OSError as exc:
                duration = (perf_counter() - start) * 1000
                return ScannerCommandResult(
                    command=module_plan.command,
                    stdout="",
                    stderr="",
                    success=False,
                    duration_ms=duration,
                    error_code="scanner_config_error",
                    error=f"scanner execution failed: {exc}",
                )

            duration = (perf_counter() - start) * 1000
            if completed.returncode != 0:
                return ScannerCommandResult(
                    command=module_plan.command,
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                    success=False,
                    duration_ms=duration,
                    exit_code=completed.returncode,
                    error_code="scanner_nonzero_exit",
                    error=f"scanner exited with code {completed.returncode}",
                    metadata={
                        "cache": {
                            "tool": self.scanner_name,
                            "cached_modules": len(modules),
                            "cache_hits": cache_hits,
                            "cache_misses": cache_misses,
                            "module_results": module_updates,
                        }
                    },
                )
            artifact = BuildRunner.resolve_first_existing(module.module_path, module_plan.artifact_candidates)
            if artifact is None:
                return ScannerCommandResult(
                    command=module_plan.command,
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                    success=False,
                    duration_ms=duration,
                    exit_code=completed.returncode,
                    error_code="scanner_output_invalid",
                    error="scanner artifact not found after successful build execution",
                    metadata={
                        "cache": {
                            "tool": self.scanner_name,
                            "cached_modules": len(modules),
                            "cache_hits": cache_hits,
                            "cache_misses": cache_misses,
                            "module_results": module_updates,
                        }
                    },
                )
            content = artifact.read_text(encoding="utf-8", errors="ignore")
            collected_artifact_contents.append(content)
            manifest = cache_service.save_manifest(
                module=module,
                tool=self.scanner_name,
                cache_key=cache_key,
                artifact_paths=[artifact],
                input_hashes=input_hashes,
                status="miss",
                reasons=miss_reasons,
                previous_cache_key=previous_manifest.cache_key if previous_manifest else None,
                previous_manifest=previous_manifest,
            )
            last_cache_update = manifest.created_at

        merged_output = self._merge_contents(collected_artifact_contents)
        duration = 0.0
        return ScannerCommandResult(
            command=plan.command,
            stdout=merged_output,
            stderr="",
            success=True,
            duration_ms=duration,
            exit_code=0,
            metadata={
                "cache": {
                    "tool": self.scanner_name,
                    "cached_modules": len(modules),
                    "cache_hits": cache_hits,
                    "cache_misses": cache_misses,
                    "miss_reason_counts": miss_reason_counts,
                    "last_cache_update": last_cache_update,
                    "module_results": module_updates,
                }
            },
        )

    def _tasks_for_runner(self, runner: BuildRunner) -> Sequence[str]:
        return self.maven_tasks if runner.runner_name == "maven" else self.gradle_tasks

    def _artifacts_for_runner(self, runner: BuildRunner) -> Sequence[str]:
        return self.maven_artifact_paths if runner.runner_name == "maven" else self.gradle_artifact_paths

    @staticmethod
    def _merge_contents(contents: list[str]) -> str:
        if not contents:
            return ""
        stripped = [item.lstrip() for item in contents if item.strip()]
        if not stripped:
            return ""
        if all(item.startswith("<") for item in stripped):
            return "<codegauge-artifacts>\n" + "\n".join(contents) + "\n</codegauge-artifacts>"
        if all(item.startswith("{") or item.startswith("[") for item in stripped):
            try:
                parsed = [json.loads(item) for item in contents]
                return json.dumps(parsed)
            except json.JSONDecodeError:
                return "\n".join(contents)
        return "\n".join(contents)
