from __future__ import annotations

from typing import Iterable

from ..parsers.base import ScannerParser


class ParserRegistryError(ValueError):
    """Raised for parser registry configuration issues."""


class DuplicateParserRegistrationError(ParserRegistryError):
    """Raised when multiple parsers are registered for the same scanner."""


class ParserRegistry:
    def __init__(self, parsers: Iterable[ScannerParser] | None = None) -> None:
        self._scanner_to_parser: dict[str, ScannerParser] = {}
        self._parsers: dict[str, ScannerParser] = {}
        for parser in parsers or []:
            self.register(parser)

    def register(self, parser: ScannerParser) -> None:
        self._parsers[parser.parser_name] = parser
        for scanner_name in parser.supported_scanners:
            if scanner_name in self._scanner_to_parser:
                existing = self._scanner_to_parser[scanner_name]
                raise DuplicateParserRegistrationError(
                    f"Scanner '{scanner_name}' already mapped to parser '{existing.parser_name}'"
                )
            self._scanner_to_parser[scanner_name] = parser

    def get(self, scanner_name: str) -> ScannerParser | None:
        return self._scanner_to_parser.get(scanner_name)

    def available_parsers(self) -> list[str]:
        return sorted(self._parsers.keys())

    def available_scanners(self) -> list[str]:
        return sorted(self._scanner_to_parser.keys())

    def expected_parser(self, scanner_name: str) -> str:
        parser = self.get(scanner_name)
        if parser is not None:
            return parser.parser_name
        return f"{scanner_name}_parser"
