from __future__ import annotations

from typing import Iterable, Sequence

from ..scanners import Scanner


class ScannerRegistry:
    def __init__(
        self,
        scanners: Iterable[Scanner],
        *,
        enabled_names: set[str] | None = None,
        disabled_names: set[str] | None = None,
    ) -> None:
        self.scanners = list(scanners)
        self.enabled_names = enabled_names
        self.disabled_names = disabled_names or set()

    def register(self, scanner: Scanner) -> None:
        self.scanners.append(scanner)

    def _name_is_enabled(self, scanner_name: str) -> bool:
        if self.enabled_names and scanner_name not in self.enabled_names:
            return False
        if scanner_name in self.disabled_names:
            return False
        return True

    def scanners_for_language(self, language: str) -> list[Scanner]:
        return [
            s
            for s in self.scanners
            if language in s.supported_languages and self._name_is_enabled(s.scanner_name)
        ]

    def enabled_scanners(self, languages: Iterable[str]) -> list[Scanner]:
        language_set = set(languages)
        return [
            s
            for s in self.scanners
            if language_set.intersection(s.supported_languages) and self._name_is_enabled(s.scanner_name)
        ]
