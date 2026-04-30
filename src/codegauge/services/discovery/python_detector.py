from __future__ import annotations

import re
from pathlib import Path

from ...profiles import DjangoProfile, ProfileRegistry
from .base import DiscoveryHelper

_DRF_RE = re.compile(r"\b(rest_framework|from\s+rest_framework|import\s+rest_framework)\b", re.IGNORECASE)
_CHANNELS_RE = re.compile(r"\b(channels|daphne|asgi\.py|ProtocolTypeRouter)\b", re.IGNORECASE)
_DJANGO_IMPORT_RE = re.compile(r"\b(from\s+django\b|import\s+django\b|django\.)", re.IGNORECASE)
_DJANGO_SETTINGS_RE = re.compile(
    r"\b(DEBUG\s*=|ALLOWED_HOSTS\s*=|SECURE_[A-Z_]+\s*=|CSRF_COOKIE_SECURE\s*=|SESSION_COOKIE_SECURE\s*=)",
    re.IGNORECASE,
)
_DJANGO_ORM_RE = re.compile(r"\b(models\.|Model\)|select_related\(|prefetch_related\(|db_index=)", re.IGNORECASE)
_FASTAPI_IMPORT_RE = re.compile(r"\b(from\s+fastapi\s+import|import\s+fastapi\b)", re.IGNORECASE)
_FASTAPI_APP_RE = re.compile(r"\bFastAPI\s*\(")
_FASTAPI_ROUTER_RE = re.compile(r"\bAPIRouter\s*\(")
_FLASK_IMPORT_RE = re.compile(r"\b(from\s+flask\s+import|import\s+flask\b)", re.IGNORECASE)
_FLASK_APP_RE = re.compile(r"\bFlask\s*\(")
_FLASK_BLUEPRINT_RE = re.compile(r"\bBlueprint\s*\(")


class PythonDetector:
    def __init__(self, profile_registry: ProfileRegistry) -> None:
        self.profile_registry = profile_registry

    @staticmethod
    def is_python_project(root: Path) -> bool:
        if (root / "pyproject.toml").exists() or (root / "requirements.txt").exists():
            return True
        return (root / "manage.py").exists()

    def detect(self, root: Path) -> dict[str, object]:
        metadata: dict[str, object] = {}
        django_meta = self._discover_django_metadata(root)
        if django_meta is not None:
            metadata["django"] = django_meta
            metadata["python_framework"] = "django"
            metadata["python_runtime"] = {
                "language": "python",
                "framework": "django",
                "framework_confidence": 0.98,
            }
            return metadata

        framework, confidence = self._detect_python_framework(root)
        metadata["python_framework"] = framework
        metadata["python_runtime"] = {
            "language": "python",
            "framework": framework,
            "framework_confidence": confidence,
        }
        return metadata

    def _detect_python_framework(self, root: Path) -> tuple[str, float]:
        py_sources = DiscoveryHelper.filtered_rglob(root, "*.py", limit=2000)
        fastapi_signals = 0
        if DiscoveryHelper.files_match(py_sources, _FASTAPI_IMPORT_RE):
            fastapi_signals += 1
        if DiscoveryHelper.files_match(py_sources, _FASTAPI_APP_RE):
            fastapi_signals += 1
        if DiscoveryHelper.files_match(py_sources, _FASTAPI_ROUTER_RE):
            fastapi_signals += 1
        if fastapi_signals > 0:
            return "fastapi", 0.55 + (0.15 * fastapi_signals)

        flask_signals = 0
        if DiscoveryHelper.files_match(py_sources, _FLASK_IMPORT_RE):
            flask_signals += 1
        if DiscoveryHelper.files_match(py_sources, _FLASK_APP_RE):
            flask_signals += 1
        if DiscoveryHelper.files_match(py_sources, _FLASK_BLUEPRINT_RE):
            flask_signals += 1
        if flask_signals > 0:
            return "flask", 0.55 + (0.15 * flask_signals)

        return "generic", 0.4

    def _discover_django_metadata(self, root: Path) -> dict[str, object] | None:
        manage_py = root / "manage.py"
        settings_files = DiscoveryHelper.filtered_rglob(root, "settings.py", limit=200)
        requirements = root / "requirements.txt"
        pyproject = root / "pyproject.toml"
        py_sources = DiscoveryHelper.filtered_rglob(root, "*.py", limit=2000)
        evidence: list[str] = []

        manage_has_django = manage_py.exists() and DiscoveryHelper.contains_any(manage_py, ("django", "DJANGO_SETTINGS_MODULE"))
        deps_has_django = (
            (requirements.exists() and DiscoveryHelper.contains_any(requirements, ("django",)))
            or (pyproject.exists() and DiscoveryHelper.contains_any(pyproject, ("django",)))
        )
        imports_has_django = DiscoveryHelper.files_match(py_sources, _DJANGO_IMPORT_RE)

        if manage_has_django:
            evidence.append("manage.py")
        if deps_has_django and requirements.exists() and DiscoveryHelper.contains_any(requirements, ("django",)):
            evidence.append("requirements.txt")
        if deps_has_django and pyproject.exists() and DiscoveryHelper.contains_any(pyproject, ("django",)):
            evidence.append("pyproject.toml")
        if imports_has_django:
            evidence.append("django_imports")
        if settings_files:
            evidence.append("settings.py")

        if not (manage_has_django or deps_has_django or imports_has_django):
            return None

        profile_spec = self.profile_registry.get("django")
        profile = DjangoProfile() if profile_spec is None else profile_spec
        html_templates = DiscoveryHelper.filtered_rglob(root, "templates/**/*.html", limit=1000)

        drf_detected = DiscoveryHelper.files_match(py_sources, _DRF_RE)
        channels_detected = DiscoveryHelper.files_match(py_sources, _CHANNELS_RE)
        settings_hardening_detected = DiscoveryHelper.files_match(settings_files, _DJANGO_SETTINGS_RE)
        orm_patterns_detected = DiscoveryHelper.files_match(py_sources, _DJANGO_ORM_RE)

        return {
            "detected": True,
            "evidence": sorted(set(evidence)),
            "frameworks": ["django"],
            "drf": drf_detected,
            "channels": channels_detected,
            "manage_py": manage_py.exists(),
            "settings_files": [path.relative_to(root).as_posix() for path in settings_files[:50]],
            "template_count": len(html_templates),
            "orm_patterns": orm_patterns_detected,
            "settings_hardening_markers": settings_hardening_detected,
            "profile": {
                "scanners": list(profile.scanners),
                "parsers": list(profile.parsers),
                "metric_providers": list(profile.metric_providers),
                "cards": list(profile.cards),
                "policy_extensions": list(profile.policy_extensions),
                "cache_behavior": profile.cache_behavior,
            },
        }
