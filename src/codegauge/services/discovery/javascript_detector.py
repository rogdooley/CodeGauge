from __future__ import annotations

from pathlib import Path

from ...domain.models import Language
from ...profiles import JavaScriptProfile, ProfileRegistry, TypeScriptProfile
from .base import DiscoveryHelper

_JS_FRAMEWORK_MARKERS: dict[str, tuple[str, ...]] = {
    "react": ("react", "react-dom", "next"),
    "nextjs": ("next",),
    "vue": ("vue", "nuxt"),
    "nuxt": ("nuxt",),
    "angular": ("@angular/core",),
    "svelte": ("svelte", "@sveltejs/kit"),
    "node": ("express", "koa", "fastify", "hapi"),
}


class JavaScriptDetector:
    def __init__(self, profile_registry: ProfileRegistry) -> None:
        self.profile_registry = profile_registry

    def detect(self, root: Path) -> dict[str, object] | None:
        package_json = root / "package.json"
        if not package_json.exists():
            return None
        package_payload = DiscoveryHelper.safe_read_json(package_json)
        if not isinstance(package_payload, dict):
            return None

        deps = self._extract_package_dependencies(package_payload)
        frameworks = self._detect_js_frameworks(deps)
        has_ts = (root / "tsconfig.json").exists() or bool(DiscoveryHelper.filtered_rglob(root, "*.ts", limit=1)) or bool(DiscoveryHelper.filtered_rglob(root, "*.tsx", limit=1))
        has_js = bool(DiscoveryHelper.filtered_rglob(root, "*.js", limit=1)) or bool(DiscoveryHelper.filtered_rglob(root, "*.jsx", limit=1))

        if not has_ts and not has_js:
            return None

        key = "typescript" if has_ts else "javascript"
        profile_name = "typescript" if has_ts else "javascript"
        profile_spec = self.profile_registry.get(profile_name)
        profile = (TypeScriptProfile() if has_ts else JavaScriptProfile()) if profile_spec is None else profile_spec
        languages = [Language.typescript, Language.javascript] if has_ts else [Language.javascript]
        scanners = list(profile.scanners)
        if has_ts and "typescript_diagnostics" not in scanners:
            scanners.append("typescript_diagnostics")

        metadata = {
            "package_manager": self._detect_package_manager(root),
            "package_json": "package.json",
            "frameworks": frameworks,
            "has_typescript": has_ts,
            "has_javascript": has_js,
            "dependency_count": len(deps),
            "profile": {
                "scanners": scanners,
                "parsers": list(profile.parsers),
                "metric_providers": list(profile.metric_providers),
                "cards": list(profile.cards),
                "policy_extensions": list(profile.policy_extensions),
                "cache_behavior": profile.cache_behavior,
            },
        }
        return {"key": key, "metadata": metadata, "languages": languages}

    @staticmethod
    def _detect_package_manager(root: Path) -> str:
        if (root / "pnpm-lock.yaml").exists():
            return "pnpm"
        if (root / "yarn.lock").exists():
            return "yarn"
        if (root / "package-lock.json").exists():
            return "npm"
        return "unknown"

    @staticmethod
    def _extract_package_dependencies(package_payload: dict[str, object]) -> set[str]:
        keys = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
        deps: set[str] = set()
        for key in keys:
            payload = package_payload.get(key)
            if isinstance(payload, dict):
                deps.update(str(name) for name in payload.keys())
        return deps

    @staticmethod
    def _detect_js_frameworks(deps: set[str]) -> list[str]:
        detected: list[str] = []
        for framework, markers in _JS_FRAMEWORK_MARKERS.items():
            if any(marker in deps for marker in markers):
                detected.append(framework)
        return sorted(detected)
