from __future__ import annotations

from pathlib import Path

import pytest

from codegauge.parsers.base import FindingPathInvalidError
from codegauge.parsers.base import normalize_finding_path


def test_normalize_canonical_project_relative_path(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    source = project / "src"
    source.mkdir(parents=True)
    file_path = source / "a.py"
    file_path.write_text("x = 1\n")

    normalized = normalize_finding_path(str(file_path), project)
    assert normalized == Path("src/a.py")


def test_normalize_removes_dot_prefix(tmp_path: Path) -> None:
    project = tmp_path / "repo2"
    project.mkdir()
    normalized = normalize_finding_path("./src/codegauge/cli.py", project)
    assert normalized == Path("src/codegauge/cli.py")


def test_normalize_best_effort_preserves_raw_path_marker(tmp_path: Path) -> None:
    project = tmp_path / "repo3"
    project.mkdir()
    raw_payload: dict[str, str] = {}
    external = (tmp_path / "outside.py").resolve()
    with pytest.raises(FindingPathInvalidError):
        normalize_finding_path(str(external), project, raw_payload)
    assert raw_payload["raw_file_path"] == str(external)
    assert raw_payload["path_normalization"] == "invalid"


def test_normalize_rejects_traversal(tmp_path: Path) -> None:
    project = tmp_path / "repo4"
    project.mkdir()
    raw_payload: dict[str, str] = {}
    with pytest.raises(FindingPathInvalidError):
        normalize_finding_path("../outside.py", project, raw_payload)
    assert raw_payload["raw_file_path"] == "../outside.py"


def test_normalize_rejects_symlink_escape(tmp_path: Path) -> None:
    project = tmp_path / "repo5"
    project.mkdir()
    outside = tmp_path / "outside-target.py"
    outside.write_text("x = 1\n")
    link = project / "link.py"
    link.symlink_to(outside)
    raw_payload: dict[str, str] = {}
    with pytest.raises(FindingPathInvalidError):
        normalize_finding_path("link.py", project, raw_payload)
    assert raw_payload["raw_file_path"] == "link.py"
    assert raw_payload["path_normalization"] == "invalid"


def test_normalize_rejects_nested_symlink_escape(tmp_path: Path) -> None:
    project = tmp_path / "repo6"
    project.mkdir()
    nested = project / "src"
    nested.mkdir()
    outside = tmp_path / "outside-target-2.py"
    outside.write_text("x = 2\n")
    link = nested / "nested-link.py"
    link.symlink_to(outside)
    raw_payload: dict[str, str] = {}
    with pytest.raises(FindingPathInvalidError):
        normalize_finding_path("src/nested-link.py", project, raw_payload)
    assert raw_payload["raw_file_path"] == "src/nested-link.py"


def test_normalize_rejects_absolute_outside_root(tmp_path: Path) -> None:
    project = tmp_path / "repo7"
    project.mkdir()
    outside = (tmp_path / "outside-absolute.py").resolve()
    outside.write_text("x = 3\n")
    raw_payload: dict[str, str] = {}
    with pytest.raises(FindingPathInvalidError):
        normalize_finding_path(str(outside), project, raw_payload)
    assert raw_payload["raw_file_path"] == str(outside)


def test_normalize_rejects_malformed_path(tmp_path: Path) -> None:
    project = tmp_path / "repo8"
    project.mkdir()
    raw_payload: dict[str, str] = {}
    with pytest.raises(FindingPathInvalidError):
        normalize_finding_path("\0bad-path", project, raw_payload)
