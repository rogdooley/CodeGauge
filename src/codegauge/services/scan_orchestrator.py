from __future__ import annotations

from datetime import datetime, UTC
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
                        },
                    )
                )
                continue

            try:
                command_result = scanner.execute(project.path)
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
