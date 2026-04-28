from __future__ import annotations

import json
import re
from pathlib import Path

from ..domain.models import Language, Project
from ..profiles import (
    DjangoProfile,
    JavaFramework,
    JavaFrameworkProfile,
    InfrastructureProfile,
    JavaProfile,
    JavaScriptProfile,
    ProfileRegistry,
    TypeScriptProfile,
)

_JAVA_BUILD_MARKERS = (
    "pom.xml",
    "mvnw",
    "build.gradle",
    "build.gradle.kts",
    "gradlew",
    "settings.gradle",
    "settings.gradle.kts",
)

_SPRING_COORDINATE_RE = re.compile(r"org\.springframework(?:\.boot)?", re.IGNORECASE)
_MICRONAUT_COORDINATE_RE = re.compile(r"io\.micronaut", re.IGNORECASE)
_QUARKUS_COORDINATE_RE = re.compile(r"io\.quarkus", re.IGNORECASE)
_JAKARTA_COORDINATE_RE = re.compile(r"jakarta\.[a-z0-9_.-]+", re.IGNORECASE)

_SPRING_ANNOTATION_PATTERNS: dict[str, re.Pattern[str]] = {
    "spring_component_annotations": re.compile(r"@(?:RestController|Controller|Service|Component|Repository)\b"),
    "spring_security_annotations": re.compile(r"@(?:PreAuthorize|Secured|RolesAllowed)\b"),
    "spring_validation_annotations": re.compile(r"@(?:Valid|Validated)\b"),
    "spring_jpa_annotations": re.compile(r"@(?:Entity|Table|ManyToOne|OneToMany)\b"),
}

_DRF_RE = re.compile(r"\b(rest_framework|from\s+rest_framework|import\s+rest_framework)\b", re.IGNORECASE)
_CHANNELS_RE = re.compile(r"\b(channels|daphne|asgi\.py|ProtocolTypeRouter)\b", re.IGNORECASE)
_DJANGO_IMPORT_RE = re.compile(r"\b(from\s+django\b|import\s+django\b|django\.)", re.IGNORECASE)
_DJANGO_SETTINGS_RE = re.compile(
    r"\b(DEBUG\s*=|ALLOWED_HOSTS\s*=|SECURE_[A-Z_]+\s*=|CSRF_COOKIE_SECURE\s*=|SESSION_COOKIE_SECURE\s*=)",
    re.IGNORECASE,
)
_DJANGO_ORM_RE = re.compile(r"\b(models\.|Model\)|select_related\(|prefetch_related\(|db_index=)", re.IGNORECASE)

_JS_FRAMEWORK_MARKERS: dict[str, tuple[str, ...]] = {
    "react": ("react", "react-dom", "next"),
    "nextjs": ("next",),
    "vue": ("vue", "nuxt"),
    "nuxt": ("nuxt",),
    "angular": ("@angular/core",),
    "svelte": ("svelte", "@sveltejs/kit"),
    "node": ("express", "koa", "fastify", "hapi"),
}

_INFRA_DISCOVERY_PATTERNS: dict[str, tuple[str, ...]] = {
    "dockerfiles": ("Dockerfile", "Containerfile"),
    "compose": ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"),
    "quadlets": ("*.container", "*.kube", "*.volume", "*.network"),
    "traefik": ("*traefik*.yml", "*traefik*.yaml", "*traefik*.toml"),
    "apache": ("httpd.conf", "apache2.conf", "*.apache.conf"),
    "nginx": ("nginx.conf", "*.nginx.conf"),
    "terraform": ("*.tf", "*.tfvars"),
    "shell": ("*.sh",),
}


class ProjectDiscoveryService:
    def __init__(self, profile_registry: ProfileRegistry | None = None) -> None:
        self.profile_registry = profile_registry or ProfileRegistry.with_builtins()

    def discover(self, path: Path) -> Project:
        language_hints: list[Language] = []
        metadata: dict[str, object] = {}

        if self._is_python_project(path):
            language_hints.append(Language.python)

        if any((path / marker).exists() for marker in _JAVA_BUILD_MARKERS):
            language_hints.append(Language.java)
            metadata["java"] = self._discover_java_metadata(path)

        django_meta = self._discover_django_metadata(path)
        if django_meta is not None:
            metadata["django"] = django_meta

        js_meta = self._discover_js_metadata(path)
        if js_meta is not None:
            metadata[js_meta["key"]] = js_meta["metadata"]
            for lang in js_meta["languages"]:
                if lang not in language_hints:
                    language_hints.append(lang)

        infra_meta = self._discover_infrastructure_metadata(path)
        if infra_meta is not None:
            metadata["infrastructure"] = infra_meta
            if Language.general not in language_hints:
                language_hints.append(Language.general)

        return Project(name=path.name, path=path, language_hints=language_hints, metadata=metadata)

    @staticmethod
    def _is_python_project(root: Path) -> bool:
        if (root / "pyproject.toml").exists() or (root / "requirements.txt").exists():
            return True
        return (root / "manage.py").exists()

    def _discover_django_metadata(self, root: Path) -> dict[str, object] | None:
        manage_py = root / "manage.py"
        settings_files = sorted(root.rglob("settings.py"))[:200]
        requirements = root / "requirements.txt"
        pyproject = root / "pyproject.toml"
        py_sources = list(root.rglob("*.py"))[:2000]
        evidence: list[str] = []

        manage_has_django = manage_py.exists() and self._contains_any(manage_py, ("django", "DJANGO_SETTINGS_MODULE"))
        deps_has_django = (
            (requirements.exists() and self._contains_any(requirements, ("django",)))
            or (pyproject.exists() and self._contains_any(pyproject, ("django",)))
        )
        imports_has_django = self._files_match(py_sources, _DJANGO_IMPORT_RE)

        if manage_has_django:
            evidence.append("manage.py")
        if deps_has_django and requirements.exists() and self._contains_any(requirements, ("django",)):
            evidence.append("requirements.txt")
        if deps_has_django and pyproject.exists() and self._contains_any(pyproject, ("django",)):
            evidence.append("pyproject.toml")
        if imports_has_django:
            evidence.append("django_imports")
        if settings_files:
            evidence.append("settings.py")

        # Fail closed for framework detection: settings.py by itself is not enough
        # because many non-Django apps (e.g. FastAPI) use the same filename.
        if not (manage_has_django or deps_has_django or imports_has_django):
            return None

        profile_spec = self.profile_registry.get("django")
        profile = DjangoProfile() if profile_spec is None else profile_spec
        html_templates = list(root.rglob("templates/**/*.html"))[:1000]

        drf_detected = self._files_match(py_sources, _DRF_RE)
        channels_detected = self._files_match(py_sources, _CHANNELS_RE)
        settings_hardening_detected = self._files_match(settings_files, _DJANGO_SETTINGS_RE)
        orm_patterns_detected = self._files_match(py_sources, _DJANGO_ORM_RE)

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

    def _discover_js_metadata(self, root: Path) -> dict[str, object] | None:
        package_json = root / "package.json"
        if not package_json.exists():
            return None
        package_payload = self._safe_read_json(package_json)
        if not isinstance(package_payload, dict):
            return None

        deps = self._extract_package_dependencies(package_payload)
        frameworks = self._detect_js_frameworks(deps)
        has_ts = (root / "tsconfig.json").exists() or any(root.rglob("*.ts")) or any(root.rglob("*.tsx"))
        has_js = any(root.rglob("*.js")) or any(root.rglob("*.jsx"))

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

    def _discover_infrastructure_metadata(self, root: Path) -> dict[str, object] | None:
        matches: dict[str, list[str]] = {}
        for key, patterns in _INFRA_DISCOVERY_PATTERNS.items():
            found: list[Path] = []
            for pattern in patterns:
                found.extend(root.rglob(pattern))
            unique = sorted({path for path in found if path.is_file()})
            matches[key] = [path.relative_to(root).as_posix() for path in unique[:100]]

        total_detected = sum(len(items) for items in matches.values())
        if total_detected == 0:
            return None

        profile_spec = self.profile_registry.get("infrastructure")
        profile = InfrastructureProfile() if profile_spec is None else profile_spec
        frameworks: list[str] = []
        if matches["dockerfiles"]:
            frameworks.append("containers")
        if matches["compose"] or matches["quadlets"]:
            frameworks.append("orchestration")
        if matches["traefik"] or matches["apache"] or matches["nginx"]:
            frameworks.append("reverse_proxy")
        if matches["terraform"]:
            frameworks.append("terraform")
        if matches["shell"]:
            frameworks.append("shell")

        return {
            "detected": True,
            "frameworks": sorted(frameworks),
            "dockerfiles": matches["dockerfiles"],
            "compose_files": matches["compose"],
            "quadlets": matches["quadlets"],
            "traefik_configs": matches["traefik"],
            "apache_configs": matches["apache"],
            "nginx_configs": matches["nginx"],
            "terraform_files": matches["terraform"],
            "shell_scripts": matches["shell"],
            "profile": {
                "scanners": list(profile.scanners),
                "parsers": list(profile.parsers),
                "metric_providers": list(profile.metric_providers),
                "cards": list(profile.cards),
                "policy_extensions": list(profile.policy_extensions),
                "cache_behavior": profile.cache_behavior,
            },
        }

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

    def _discover_java_metadata(self, root: Path) -> dict[str, object]:
        module_files = self._discover_java_modules(root)
        frameworks = self._discover_java_frameworks(root, module_files)
        spring = self._discover_spring_metadata(root)
        framework_profiles = tuple(
            JavaFrameworkProfile(
                framework=framework,
                detected=detected,
                evidence=tuple(evidence),
            )
            for framework, detected, evidence in frameworks
        )
        profile_spec = self.profile_registry.get("java")
        profile = JavaProfile(frameworks=framework_profiles) if profile_spec is None else JavaProfile(
            frameworks=framework_profiles,
            scanners=profile_spec.scanners,
            parsers=profile_spec.parsers,
            metric_providers=profile_spec.metric_providers,
            cards=profile_spec.cards,
            policy_extensions=profile_spec.policy_extensions,
            cache_behavior=profile_spec.cache_behavior,
        )
        return {
            "module_count": len(module_files),
            "multi_module": len(module_files) > 1,
            "modules": [module.relative_to(root).as_posix() for module in module_files],
            "frameworks": [entry.framework.value for entry in profile.frameworks if entry.detected],
            "framework_evidence": {
                entry.framework.value: list(entry.evidence)
                for entry in profile.frameworks
                if entry.detected
            },
            "profile": {
                "scanners": list(profile.scanners),
                "parsers": list(profile.parsers),
                "metric_providers": list(profile.metric_providers),
                "cards": list(profile.cards),
                "policy_extensions": list(profile.policy_extensions),
                "cache_behavior": profile.cache_behavior,
            },
            "spring": spring,
        }

    @staticmethod
    def _discover_java_modules(root: Path) -> list[Path]:
        markers = {"pom.xml", "build.gradle", "build.gradle.kts"}
        module_files: list[Path] = []
        for marker in markers:
            module_files.extend(root.rglob(marker))
        unique = sorted({path.parent for path in module_files})
        return unique or [root]

    def _discover_java_frameworks(
        self,
        root: Path,
        modules: list[Path],
    ) -> list[tuple[JavaFramework, bool, list[str]]]:
        _ = root
        build_files: list[Path] = []
        for module in modules:
            for name in ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"):
                candidate = module / name
                if candidate.exists():
                    build_files.append(candidate)
        consolidated = "\n".join(self._safe_read_text(path) for path in build_files)
        frameworks: list[tuple[JavaFramework, bool, list[str]]] = []
        frameworks.append(
            (
                JavaFramework.spring,
                bool(_SPRING_COORDINATE_RE.search(consolidated)),
                self._framework_evidence(build_files, _SPRING_COORDINATE_RE),
            )
        )
        frameworks.append(
            (
                JavaFramework.spring_boot,
                "spring-boot" in consolidated.lower() or "org.springframework.boot" in consolidated.lower(),
                self._framework_evidence(
                    build_files,
                    re.compile(r"(spring-boot|org\.springframework\.boot)", re.IGNORECASE),
                ),
            )
        )
        frameworks.append(
            (
                JavaFramework.micronaut,
                bool(_MICRONAUT_COORDINATE_RE.search(consolidated)),
                self._framework_evidence(build_files, _MICRONAUT_COORDINATE_RE),
            )
        )
        frameworks.append(
            (
                JavaFramework.quarkus,
                bool(_QUARKUS_COORDINATE_RE.search(consolidated)),
                self._framework_evidence(build_files, _QUARKUS_COORDINATE_RE),
            )
        )
        frameworks.append(
            (
                JavaFramework.jakarta_ee,
                bool(_JAKARTA_COORDINATE_RE.search(consolidated)),
                self._framework_evidence(build_files, _JAKARTA_COORDINATE_RE),
            )
        )
        return frameworks

    def _discover_spring_metadata(self, root: Path) -> dict[str, object]:
        sources = list(root.rglob("*.java"))
        indicators: dict[str, bool] = {
            "security_modules": False,
            "actuator": False,
            "jpa_hibernate": False,
            "validation": False,
        }
        annotation_hits: dict[str, int] = {key: 0 for key in _SPRING_ANNOTATION_PATTERNS}
        for src in sources[:500]:
            text = self._safe_read_text(src)
            if not text:
                continue
            for key, pattern in _SPRING_ANNOTATION_PATTERNS.items():
                if pattern.search(text):
                    annotation_hits[key] += 1
            lower = text.lower()
            if "spring-security" in lower or "@enablewebsecurity" in lower:
                indicators["security_modules"] = True
            if "spring-boot-starter-actuator" in lower or "/actuator" in lower:
                indicators["actuator"] = True
            if "hibernate" in lower or "@entity" in lower:
                indicators["jpa_hibernate"] = True
            if "@valid" in text or "@validated" in text:
                indicators["validation"] = True
        return {
            **indicators,
            "annotation_hits": annotation_hits,
        }

    @staticmethod
    def _framework_evidence(files: list[Path], pattern: re.Pattern[str]) -> list[str]:
        evidence: list[str] = []
        for file in files:
            try:
                text = file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if pattern.search(text):
                evidence.append(file.name)
        return evidence[:20]

    @staticmethod
    def _safe_read_text(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    @staticmethod
    def _safe_read_json(path: Path) -> dict[str, object] | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if isinstance(payload, dict):
            return payload
        return None

    @staticmethod
    def _files_match(files: list[Path], pattern: re.Pattern[str]) -> bool:
        for file in files[:500]:
            text = ProjectDiscoveryService._safe_read_text(file)
            if pattern.search(text):
                return True
        return False

    @staticmethod
    def _contains_any(path: Path, needles: tuple[str, ...]) -> bool:
        text = ProjectDiscoveryService._safe_read_text(path)
        lowered = text.lower()
        return any(needle.lower() in lowered for needle in needles)
