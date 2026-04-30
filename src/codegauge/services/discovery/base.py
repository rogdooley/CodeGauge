from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol


_DISCOVERY_IGNORED_PARTS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    "site-packages",
}


class DiscoveryDetector(Protocol):
    def detect(self, root: Path) -> dict[str, object] | None: ...


class DiscoveryHelper:
    @staticmethod
    def safe_read_text(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    @staticmethod
    def safe_read_json(path: Path) -> dict[str, object] | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if isinstance(payload, dict):
            return payload
        return None

    @classmethod
    def filtered_rglob(cls, root: Path, pattern: str, *, limit: int | None = None) -> list[Path]:
        results: list[Path] = []
        for candidate in root.rglob(pattern):
            if cls.is_discovery_ignored(candidate, root):
                continue
            results.append(candidate)
            if limit is not None and len(results) >= limit:
                break
        return results

    @classmethod
    def files_match(cls, files: list[Path], pattern) -> bool:
        for file in files[:500]:
            text = cls.safe_read_text(file)
            if pattern.search(text):
                return True
        return False

    @classmethod
    def contains_any(cls, path: Path, needles: tuple[str, ...]) -> bool:
        text = cls.safe_read_text(path)
        lowered = text.lower()
        return any(needle.lower() in lowered for needle in needles)

    @staticmethod
    def is_discovery_ignored(path: Path, root: Path) -> bool:
        try:
            rel = path.relative_to(root)
        except ValueError:
            return True
        return any(part in _DISCOVERY_IGNORED_PARTS for part in rel.parts)
