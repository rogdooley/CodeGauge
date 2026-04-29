from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def default_state_root() -> Path:
    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "CodeGauge"
    if sys.platform.startswith("win"):
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / "CodeGauge"
        return home / "AppData" / "Local" / "CodeGauge"
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home) / "codegauge"
    return home / ".local" / "share" / "codegauge"


def default_report_root() -> Path:
    home = Path.home()
    if sys.platform.startswith("win"):
        user_profile = os.environ.get("USERPROFILE")
        if user_profile:
            return Path(user_profile) / "Documents" / "CodeGauge"
    return home / "Documents" / "CodeGauge"


def gui_session_available() -> bool:
    if sys.platform.startswith("win"):
        return True
    if sys.platform == "darwin":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def open_in_browser(target: Path) -> tuple[bool, str]:
    resolved = target.expanduser().resolve()
    if not resolved.exists():
        return False, f"portal file not found: {resolved}"
    if not gui_session_available():
        return False, "no GUI session detected; skipped opening browser"
    try:
        if sys.platform == "darwin":
            subprocess.run(["open", str(resolved)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, f"opened {resolved}"
        if sys.platform.startswith("win"):
            os.startfile(str(resolved))  # type: ignore[attr-defined]
            return True, f"opened {resolved}"
        opener = shutil.which("xdg-open")
        if opener is None:
            return False, "xdg-open not found; cannot open browser"
        subprocess.run([opener, str(resolved)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True, f"opened {resolved}"
    except Exception as exc:
        return False, f"failed to open browser: {exc}"


def java_cache_root_for_project(state_root: Path, project_root: Path) -> Path:
    import hashlib

    resolved_project = project_root.expanduser().resolve()
    key = hashlib.sha1(str(resolved_project).encode("utf-8")).hexdigest()[:12]
    return state_root / "cache" / "java" / f"{resolved_project.name}-{key}" / "modules"
