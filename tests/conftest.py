from __future__ import annotations

import re
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolate_codegauge_user_dirs(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    scratch_root = repo_root / ".scratch" / "pytest-home"
    safe_node = re.sub(r"[^A-Za-z0-9_.-]+", "_", request.node.nodeid)
    fake_home = scratch_root / safe_node
    fake_home.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setenv("LOCALAPPDATA", str(fake_home / "AppData" / "Local"))
    monkeypatch.setenv("XDG_DATA_HOME", str(fake_home / ".local" / "share"))
