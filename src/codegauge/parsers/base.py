from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

from ..domain.models import Finding


class ScannerParseError(ValueError):
    """Raised when scanner output cannot be parsed semantically."""


class ScannerOutputInvalidError(ScannerParseError):
    """Raised when scanner output is malformed or not expected JSON structure."""


class FindingPathInvalidError(ScannerParseError):
    """Raised when a finding path cannot be safely normalized under project root."""

    def __init__(self, message: str, raw_payload: dict | None = None) -> None:
        super().__init__(message)
        self.raw_payload = raw_payload or {}


class ScannerParser(ABC):
    parser_name: str
    supported_scanners: tuple[str, ...]

    @abstractmethod
    def parse(self, stdout: str, stderr: str, project_path: Path) -> Sequence[Finding]:
        ...

    def parse_metadata(self, stdout: str, stderr: str, project_path: Path) -> dict[str, Any]:
        return {}


def normalize_finding_path(path_value: str, project_path: Path, raw_payload: dict | None = None) -> Path:
    project_root = project_path.resolve()
    raw_path = str(path_value)
    try:
        candidate = Path(raw_path).expanduser()
    except (TypeError, ValueError) as exc:
        if raw_payload is not None:
            raw_payload["raw_file_path"] = raw_path
            raw_payload["path_normalization"] = "invalid"
            raw_payload["path_error"] = str(exc)
        raise FindingPathInvalidError(f"invalid finding path format: {raw_path}", raw_payload=dict(raw_payload or {})) from exc

    if not candidate.is_absolute():
        # Reject traversal escapes before normalization.
        if any(part == ".." for part in candidate.parts):
            if raw_payload is not None:
                raw_payload["raw_file_path"] = raw_path
                raw_payload["path_normalization"] = "invalid"
                raw_payload["path_error"] = "path traversal segment detected"
            raise FindingPathInvalidError(
                f"invalid finding path outside project root: {raw_path}",
                raw_payload=dict(raw_payload or {}),
            )
    try:
        absolute = candidate.resolve(strict=False) if candidate.is_absolute() else (project_root / candidate).resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        if raw_payload is not None:
            raw_payload["raw_file_path"] = raw_path
            raw_payload["path_normalization"] = "invalid"
            raw_payload["path_error"] = str(exc)
        raise FindingPathInvalidError(f"invalid finding path outside project root: {raw_path}", raw_payload=dict(raw_payload or {})) from exc

    try:
        relative = absolute.relative_to(project_root)
        normalized = Path(PurePosixPath(relative.as_posix()))
        if str(normalized).startswith(".."):
            raise ValueError("path traversal outside project root")
        if raw_payload is not None:
            raw_payload["path_normalization"] = "canonical"
        return normalized
    except ValueError as exc:
        if raw_payload is not None:
            raw_payload["raw_file_path"] = raw_path
            raw_payload["path_normalization"] = "invalid"
            raw_payload["path_error"] = str(exc)
        raise FindingPathInvalidError(
            f"invalid finding path outside project root: {raw_path}",
            raw_payload=dict(raw_payload or {}),
        ) from exc
