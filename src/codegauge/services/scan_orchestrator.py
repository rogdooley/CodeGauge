from __future__ import annotations

from datetime import datetime, UTC
import fnmatch
from pathlib import Path
from typing import Sequence

from ..domain.models import ScanResult, Project
from ..parsers import FindingPathInvalidError, ScannerOutputInvalidError, ScannerParseError
from .report_normalizer import parser_finding
from .parser_registry import ParserRegistry
from .scanner_registry import ScannerRegistry


class ScanOrchestrator:
    def __init__(self, registry: ScannerRegistry, parser_registry: ParserRegistry) -> None:
        self.registry = registry
        self.parser_registry = parser_registry

    def run(self, project: Project) -> Sequence[ScanResult]:
        results: list[ScanResult] = []
        for scanner in self.registry.enabled_scanners([lang.value for lang in project.language_hints]):
            started_at = datetime.now(UTC)
            scanner_files = self._scanner_input_files(project, scanner.supported_languages)
            if not scanner_files:
                completed_at = datetime.now(UTC)
                duration_ms = (completed_at - started_at).total_seconds() * 1000
                results.append(
                    ScanResult(
                        scanner_name=scanner.scanner_name,
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_ms=duration_ms,
                        findings=[],
                        success=True,
                        metadata={
                            "error_code": None,
                            "command": None,
                            "stdout": "",
                            "stderr": "",
                            "exit_code": None,
                            "duration_ms": duration_ms,
                            "scanner_input_file_count": 0,
                            "skipped_reason": "no_candidate_files",
                        },
                    )
                )
                continue
            if not scanner.is_available():
                attempted_command = None
                try:
                    attempted_command = scanner.build_command(project.path)
                except Exception:
                    attempted_command = None
                completed_at = datetime.now(UTC)
                results.append(
                    ScanResult(
                        scanner_name=scanner.scanner_name,
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_ms=(completed_at - started_at).total_seconds() * 1000,
                        findings=[],
                        success=False,
                        error_code="scanner_binary_missing",
                        error=f"scanner binary not found: {scanner.scanner_name}",
                        metadata={
                            "error_code": "scanner_binary_missing",
                            "command": attempted_command,
                            "stdout": "",
                            "stderr": "",
                            "exit_code": None,
                            "duration_ms": (completed_at - started_at).total_seconds() * 1000,
                            "scanner_input_file_count": len(scanner_files),
                        },
                    )
                )
                continue

            try:
                command_result = scanner.execute(project.path, files=scanner_files)
            except Exception as exc:
                completed_at = datetime.now(UTC)
                duration_ms = (completed_at - started_at).total_seconds() * 1000
                results.append(
                    ScanResult(
                        scanner_name=scanner.scanner_name,
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_ms=duration_ms,
                        findings=[],
                        success=False,
                        error_code="scanner_config_error",
                        error=f"scanner execution failed: {exc}",
                        metadata={
                            "error_code": "scanner_config_error",
                            "command": None,
                            "stdout": "",
                            "stderr": "",
                            "exit_code": None,
                            "duration_ms": duration_ms,
                            "scanner_input_file_count": len(scanner_files),
                        },
                    )
                )
                continue
            completed_at = datetime.now(UTC)
            parse_error: str | None = None
            parse_error_code: str | None = None
            invalid_finding_payload: dict | None = None
            invalid_finding_count = 0
            parsed_metadata: dict = {}
            findings = []
            if command_result.success:
                parser = self.parser_registry.get(scanner.scanner_name)
                if parser is None:
                    parse_error = f"parser not registered for scanner: {scanner.scanner_name}"
                    parse_error_code = "scanner_parser_missing"
                else:
                    try:
                        findings = list(parser.parse(command_result.stdout, command_result.stderr, project.path))
                        parsed_metadata = parser.parse_metadata(command_result.stdout, command_result.stderr, project.path)
                    except FindingPathInvalidError as exc:
                        parse_error = None
                        parse_error_code = None
                        invalid_finding_payload = exc.raw_payload
                        invalid_finding_count = 1
                        findings = [
                            parser_finding(
                                tool=scanner.scanner_name,
                                rule_id="CODEGAUGE.PARSER.INVALID_PATH",
                                message=f"invalid finding path from scanner '{scanner.scanner_name}'",
                                raw_payload=exc.raw_payload,
                            )
                        ]
                    except ScannerOutputInvalidError as exc:
                        parse_error = None
                        parse_error_code = None
                        invalid_finding_count = 1
                        findings = [
                            parser_finding(
                                tool=scanner.scanner_name,
                                rule_id="CODEGAUGE.PARSER.SCHEMA_ERROR",
                                message=f"scanner output invalid for '{scanner.scanner_name}': {exc}",
                            )
                        ]
                    except ScannerParseError as exc:
                        parse_error = None
                        parse_error_code = None
                        invalid_finding_count = 1
                        findings = [
                            parser_finding(
                                tool=scanner.scanner_name,
                                rule_id="CODEGAUGE.PARSER.UNHANDLED",
                                message=f"scanner output parsing failed for '{scanner.scanner_name}': {exc}",
                            )
                        ]
                    except Exception as exc:
                        parse_error = None
                        parse_error_code = None
                        invalid_finding_count = 1
                        findings = [
                            parser_finding(
                                tool=scanner.scanner_name,
                                rule_id="CODEGAUGE.PARSER.UNHANDLED",
                                message=f"unexpected parser failure for '{scanner.scanner_name}': {exc}",
                            )
                        ]

            error = command_result.error or parse_error
            error_code = command_result.error_code or parse_error_code
            results.append(
                ScanResult(
                    scanner_name=scanner.scanner_name,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=command_result.duration_ms,
                    findings=findings,
                    success=error is None,
                    error_code=error_code,
                    error=error,
                    metadata={
                        "error_code": error_code,
                        "command": command_result.command,
                        "stdout": command_result.stdout,
                        "stderr": command_result.stderr,
                        "exit_code": command_result.exit_code,
                        "duration_ms": command_result.duration_ms,
                        "invalid_finding_payload": invalid_finding_payload,
                        "invalid_finding_count": invalid_finding_count,
                        "scanner_name": scanner.scanner_name,
                        "expected_parser": self.parser_registry.expected_parser(scanner.scanner_name),
                        "scanner_input_file_count": len(scanner_files),
                        "remediation": (
                            f"Register parser '{self.parser_registry.expected_parser(scanner.scanner_name)}' "
                            f"for scanner '{scanner.scanner_name}'."
                            if error_code == "scanner_parser_missing"
                            else None
                        ),
                        **(dict(command_result.metadata) if command_result.metadata else {}),
                        **parsed_metadata,
                    },
                )
            )
        return results

    @staticmethod
    def _scanner_input_files(project: Project, scanner_languages: Sequence[str]) -> list[Path]:
        language_set = set(scanner_languages)
        config = project.config if isinstance(project.config, dict) else {}
        excludes = list(config.get("exclude", [])) if isinstance(config.get("exclude", []), list) else []
        excludes.extend([".venv/**", ".git/**", ".pytest_cache/**", ".ruff_cache/**", "node_modules/**"])
        root = project.path
        patterns: set[str] = set()
        if "general" in language_set:
            patterns.add("*")
        if "python" in language_set:
            patterns.add("*.py")
        if "javascript" in language_set:
            patterns.update({"*.js", "*.jsx"})
        if "typescript" in language_set:
            patterns.update({"*.ts", "*.tsx"})
        if "java" in language_set:
            patterns.add("*.java")
        if "go" in language_set:
            patterns.add("*.go")
        if "yaml" in language_set:
            patterns.update({"*.yml", "*.yaml"})
        if "terraform" in language_set:
            patterns.update({"*.tf", "*.tfvars"})
        files: list[Path] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if patterns and not any(fnmatch.fnmatch(path.name, pattern) for pattern in patterns):
                continue
            rel = path.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(rel, pattern) for pattern in excludes):
                continue
            files.append(path)
        return files
