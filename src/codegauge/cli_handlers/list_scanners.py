from __future__ import annotations

import json

import typer

from ..bootstrap.factory import register_builtin_parsers, register_builtin_scanners
from ..services.parser_registry import ParserRegistry
from ..services.scanner_registry import ScannerRegistry


def list_scanners_handler(*, json_output: bool) -> None:
    registry = ScannerRegistry([])
    register_builtin_scanners(registry)
    parser_registry = ParserRegistry()
    register_builtin_parsers(parser_registry)
    payload: list[dict[str, str | bool]] = []
    for scanner in registry.scanners:
        available = scanner.is_available()
        parser_registered = parser_registry.get(scanner.scanner_name) is not None
        expected_parser = parser_registry.expected_parser(scanner.scanner_name)
        if not available:
            status = "unavailable"
        elif parser_registered:
            status = "ready"
        else:
            status = "incomplete"
        payload.append(
            {
                "scanner_name": scanner.scanner_name,
                "available": available,
                "parser_registered": parser_registered,
                "expected_parser": expected_parser,
                "status": status,
            }
        )
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    typer.echo("Available scanners:")
    for row in payload:
        typer.echo(
            f"- {row['scanner_name']} | available={str(row['available']).lower()} "
            f"| parser_registered={str(row['parser_registered']).lower()} "
            f"| expected_parser={row['expected_parser']} | status={row['status']}"
        )
