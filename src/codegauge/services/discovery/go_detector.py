from __future__ import annotations

import re
from pathlib import Path

from ...domain.models import Language
from ...profiles import GoProfile, ProfileRegistry
from .base import DiscoveryHelper

_GIN_RE = re.compile(r"github\.com/gin-gonic/gin", re.IGNORECASE)
_ECHO_RE = re.compile(r"github\.com/labstack/echo", re.IGNORECASE)
_FIBER_RE = re.compile(r"github\.com/gofiber/fiber", re.IGNORECASE)


class GoDetector:
    def __init__(self, profile_registry: ProfileRegistry) -> None:
        self.profile_registry = profile_registry

    @staticmethod
    def is_go_project(root: Path) -> bool:
        if (root / "go.mod").exists() or (root / "go.sum").exists():
            return True
        return bool(DiscoveryHelper.filtered_rglob(root, "*.go", limit=1))

    def detect(self, root: Path) -> dict[str, object] | None:
        go_mod = root / "go.mod"
        go_sum = root / "go.sum"
        go_files = DiscoveryHelper.filtered_rglob(root, "*.go", limit=500)
        if not go_mod.exists() and not go_sum.exists() and not go_files:
            return None

        framework = self._framework(go_mod)
        confidence = 0.9 if framework != "stdlib" else 0.5
        profile_spec = self.profile_registry.get("go")
        profile = GoProfile() if profile_spec is None else profile_spec
        return {
            "framework": framework,
            "framework_confidence": confidence,
            "go_mod": go_mod.exists(),
            "go_sum": go_sum.exists(),
            "go_file_count": len(go_files),
            "profile": {
                "scanners": list(profile.scanners),
                "parsers": list(profile.parsers),
                "metric_providers": list(profile.metric_providers),
                "cards": list(profile.cards),
                "policy_extensions": list(profile.policy_extensions),
                "cache_behavior": profile.cache_behavior,
            },
            "languages": [Language.go],
        }

    def _framework(self, go_mod: Path) -> str:
        if not go_mod.exists():
            return "stdlib"
        text = DiscoveryHelper.safe_read_text(go_mod)
        if _GIN_RE.search(text):
            return "gin"
        if _ECHO_RE.search(text):
            return "echo"
        if _FIBER_RE.search(text):
            return "fiber"
        return "stdlib"
