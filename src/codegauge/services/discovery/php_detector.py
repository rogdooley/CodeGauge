from __future__ import annotations

import re
from pathlib import Path

from ...domain.models import Language
from ...profiles import PHPProfile, ProfileRegistry
from .base import DiscoveryHelper

_PHP_LARAVEL_RE = re.compile(r"laravel|illuminate/", re.IGNORECASE)
_PHP_SYMFONY_RE = re.compile(r"symfony/", re.IGNORECASE)
_PHP_WP_RE = re.compile(r"wordpress|wp-", re.IGNORECASE)


class PHPDetector:
    def __init__(self, profile_registry: ProfileRegistry) -> None:
        self.profile_registry = profile_registry

    @staticmethod
    def is_php_project(root: Path) -> bool:
        if (root / "composer.json").exists() or (root / "composer.lock").exists():
            return True
        return bool(DiscoveryHelper.filtered_rglob(root, "*.php", limit=1))

    def detect(self, root: Path) -> dict[str, object] | None:
        composer_json = root / "composer.json"
        composer_lock = root / "composer.lock"
        php_files = DiscoveryHelper.filtered_rglob(root, "*.php", limit=500)
        if not composer_json.exists() and not composer_lock.exists() and not php_files:
            return None

        framework = self._framework(root, composer_json)
        confidence = 0.9 if framework != "generic_php" else 0.5
        profile_spec = self.profile_registry.get("php")
        profile = PHPProfile() if profile_spec is None else profile_spec
        return {
            "framework": framework,
            "framework_confidence": confidence,
            "composer_json": composer_json.exists(),
            "composer_lock": composer_lock.exists(),
            "php_file_count": len(php_files),
            "profile": {
                "scanners": list(profile.scanners),
                "parsers": list(profile.parsers),
                "metric_providers": list(profile.metric_providers),
                "cards": list(profile.cards),
                "policy_extensions": list(profile.policy_extensions),
                "cache_behavior": profile.cache_behavior,
            },
            "languages": [Language.php],
        }

    def _framework(self, root: Path, composer_json: Path) -> str:
        if composer_json.exists():
            text = DiscoveryHelper.safe_read_text(composer_json)
            if _PHP_LARAVEL_RE.search(text):
                return "laravel"
            if _PHP_SYMFONY_RE.search(text):
                return "symfony"
            if _PHP_WP_RE.search(text):
                return "wordpress"
        if (root / "artisan").exists():
            return "laravel"
        if (root / "bin" / "console").exists():
            return "symfony"
        if (root / "wp-config.php").exists():
            return "wordpress"
        return "generic_php"
