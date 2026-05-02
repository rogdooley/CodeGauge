from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import fnmatch
import subprocess
from enum import StrEnum

from ..constants import DisabledReason
from ..config import CodeGaugeConfig, load_config
from ..domain.models import Project
from ..parsers import (
    BanditParser,
    CheckstyleParser,
    ComposerAuditParser,
    ComposeScanParser,
    CoverageParser,
    DjangoCheckDeployParser,
    DjangoOrmHealthParser,
    DjangoSettingsScanParser,
    DjangoTemplateScanParser,
    DependencyCheckParser,
    DockerfileScanParser,
    ESLintParser,
    ErrorProneParser,
    GoCoverageParser,
    GoVetParser,
    GitHistorySecretsParser,
    GitleaksParser,
    GovulncheckParser,
    JaCoCoParser,
    JSCoverageParser,
    NPMAuditParser,
    OpenGrepInfraParser,
    OpenGrepJavaParser,
    OpenGrepJSParser,
    OpenGrepGoParser,
    OpenGrepPHPParser,
    OpenGrepParser,
    PMDParser,
    PHPCSParser,
    PHPStanParser,
    PyrightParser,
    QuadletScanParser,
    RadonParser,
    ReverseProxyScanParser,
    RuffParser,
    SecretsHeuristicParser,
    ShellCheckParser,
    SpotBugsParser,
    StaticcheckParser,
    TerraformScanParser,
    TypeScriptDiagnosticsParser,
    TruffleHogParser,
    VultureParser,
)
from ..scanners import (
    BanditScanner,
    CheckstyleScanner,
    ComposerAuditScanner,
    ComposeScanScanner,
    CoverageScanner,
    DockerfileScanScanner,
    DjangoCheckDeployScanner,
    DjangoOrmHealthScanner,
    DjangoSettingsScanScanner,
    DjangoTemplateScanScanner,
    DependencyCheckScanner,
    ESLintScanner,
    ErrorProneScanner,
    GoCoverageScanner,
    GoVetScanner,
    GitHistorySecretsScanner,
    GitleaksScanner,
    GovulncheckScanner,
    JaCoCoScanner,
    JSCoverageScanner,
    NpmAuditScanner,
    OpenGrepInfraScanner,
    OpenGrepJavaScanner,
    OpenGrepJSScanner,
    OpenGrepGoScanner,
    OpenGrepPHPScanner,
    OpenGrepScanner,
    PMDScanner,
    PHPCSScanner,
    PHPStanScanner,
    PyrightScanner,
    QuadletScanScanner,
    RadonScanner,
    ReverseProxyScanScanner,
    RuffScanner,
    SecretsHeuristicScanner,
    ShellCheckScanner,
    SpotBugsScanner,
    StaticcheckScanner,
    TerraformScanScanner,
    TypeScriptDiagnosticsScanner,
    TruffleHogScanner,
    VultureScanner,
)
from ..services.parser_registry import ParserRegistry
from ..services.project_discovery import ProjectDiscoveryService
from ..services.scan_orchestrator import ScanOrchestrator
from ..services.scanner_registry import ScannerRegistry
from ..profiles import ProfileRegistry


@dataclass(frozen=True)
class ScanApplicationServices:
    project_path: Path
    project: Project
    config: CodeGaugeConfig
    scanner_registry: ScannerRegistry
    parser_registry: ParserRegistry
    orchestrator: ScanOrchestrator


def register_builtin_scanners(registry: ScannerRegistry) -> None:
    registry.register(RuffScanner())
    registry.register(PyrightScanner())
    registry.register(PHPStanScanner())
    registry.register(ComposerAuditScanner())
    registry.register(PHPCSScanner())
    registry.register(OpenGrepPHPScanner())
    registry.register(GoVetScanner())
    registry.register(StaticcheckScanner())
    registry.register(GovulncheckScanner())
    registry.register(GoCoverageScanner())
    registry.register(OpenGrepGoScanner())
    registry.register(CoverageScanner())
    registry.register(RadonScanner())
    registry.register(VultureScanner())
    registry.register(BanditScanner())
    registry.register(OpenGrepScanner())
    registry.register(OpenGrepInfraScanner())
    registry.register(DockerfileScanScanner())
    registry.register(ComposeScanScanner())
    registry.register(QuadletScanScanner())
    registry.register(ReverseProxyScanScanner())
    registry.register(TerraformScanScanner())
    registry.register(ShellCheckScanner())
    registry.register(DjangoCheckDeployScanner())
    registry.register(DjangoSettingsScanScanner())
    registry.register(DjangoTemplateScanScanner())
    registry.register(DjangoOrmHealthScanner())
    registry.register(SpotBugsScanner())
    registry.register(PMDScanner())
    registry.register(CheckstyleScanner())
    registry.register(ErrorProneScanner())
    registry.register(JaCoCoScanner())
    registry.register(DependencyCheckScanner())
    registry.register(OpenGrepJavaScanner())
    registry.register(ESLintScanner())
    registry.register(TypeScriptDiagnosticsScanner())
    registry.register(NpmAuditScanner())
    registry.register(JSCoverageScanner())
    registry.register(OpenGrepJSScanner())
    registry.register(GitleaksScanner())
    registry.register(TruffleHogScanner())
    registry.register(SecretsHeuristicScanner())
    registry.register(GitHistorySecretsScanner())


def register_builtin_parsers(registry: ParserRegistry) -> None:
    registry.register(RuffParser())
    registry.register(PyrightParser())
    registry.register(PHPStanParser())
    registry.register(ComposerAuditParser())
    registry.register(PHPCSParser())
    registry.register(OpenGrepPHPParser())
    registry.register(GoVetParser())
    registry.register(StaticcheckParser())
    registry.register(GovulncheckParser())
    registry.register(GoCoverageParser())
    registry.register(OpenGrepGoParser())
    registry.register(CoverageParser())
    registry.register(RadonParser())
    registry.register(VultureParser())
    registry.register(BanditParser())
    registry.register(OpenGrepParser())
    registry.register(OpenGrepInfraParser())
    registry.register(DockerfileScanParser())
    registry.register(ComposeScanParser())
    registry.register(QuadletScanParser())
    registry.register(ReverseProxyScanParser())
    registry.register(TerraformScanParser())
    registry.register(ShellCheckParser())
    registry.register(DjangoCheckDeployParser())
    registry.register(DjangoSettingsScanParser())
    registry.register(DjangoTemplateScanParser())
    registry.register(DjangoOrmHealthParser())
    registry.register(SpotBugsParser())
    registry.register(PMDParser())
    registry.register(CheckstyleParser())
    registry.register(ErrorProneParser())
    registry.register(JaCoCoParser())
    registry.register(DependencyCheckParser())
    registry.register(OpenGrepJavaParser())
    registry.register(ESLintParser())
    registry.register(TypeScriptDiagnosticsParser())
    registry.register(NPMAuditParser())
    registry.register(JSCoverageParser())
    registry.register(OpenGrepJSParser())
    registry.register(GitleaksParser())
    registry.register(TruffleHogParser())
    registry.register(SecretsHeuristicParser())
    registry.register(GitHistorySecretsParser())


def _apply_scanner_config(scanner_registry: ScannerRegistry, config: CodeGaugeConfig) -> ScannerRegistry:
    disabled = set(config.disabled_scanners)
    for scanner in scanner_registry.scanners:
        scanner_settings = config.scanners.get(scanner.scanner_name)
        timeout_seconds = config.default_timeout_seconds
        extra_args: list[str] = []
        if scanner_settings:
            if scanner_settings.enabled is False:
                disabled.add(scanner.scanner_name)
            if scanner_settings.timeout_seconds is not None:
                timeout_seconds = scanner_settings.timeout_seconds
            extra_args = scanner_settings.extra_args
        scanner.timeout_seconds = timeout_seconds
        scanner.extra_args = list(extra_args)
        scanner.state_root = config.state_root
    enabled = set(config.enabled_scanners) or None
    return ScannerRegistry(scanner_registry.scanners, enabled_names=enabled, disabled_names=disabled)


def _build_inventory(project_root: Path, excludes: list[str]) -> dict[str, int]:
    files_seen = 0
    first_party = 0
    third_party = 0
    generated = 0
    excluded = 0
    deny = set(excludes) | {".venv/**", ".git/**", ".pytest_cache/**", ".ruff_cache/**"}
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        files_seen += 1
        rel = path.relative_to(project_root).as_posix()
        if any(fnmatch.fnmatch(rel, pattern) for pattern in deny):
            excluded += 1
            continue
        low = rel.lower()
        if any(x in low for x in ("node_modules/", "vendor/", "third_party/", ".venv/")):
            third_party += 1
        elif any(x in low for x in ("/generated/", "/dist/", "/build/", "_generated")):
            generated += 1
        else:
            first_party += 1
    return {
        "files_seen": files_seen,
        "first_party": first_party,
        "third_party": third_party,
        "generated": generated,
        "excluded": excluded,
    }


class InventoryZone(StrEnum):
    TRACKED = "tracked"
    IGNORED_SENSITIVE = "ignored_sensitive"
    DOCS = "docs"
    FIXTURE = "fixture"
    THIRD_PARTY = "third_party"
    GENERATED = "generated"
    EXCLUDED = "excluded"


SENSITIVE_IGNORED_PATTERNS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.crt",
    "*.csr",
    "*.jks",
    "*.kdbx",
    "*.ovpn",
    "*.mobileconfig",
    "secrets.*",
    "credentials.*",
    "oauth*.json",
    "service-account*.json",
    "id_rsa",
    "id_ed25519",
    "*.sqlite",
    "*.db",
)

EXCLUDED_JUNK_PATTERNS: tuple[str, ...] = (
    ".venv/**",
    "venv/**",
    "node_modules/**",
    "vendor/**",
    "dist/**",
    "build/**",
    ".cache/**",
    ".pytest_cache/**",
    ".mypy_cache/**",
    ".ruff_cache/**",
    ".scan-cache/**",
    ".codegauge/**",
    "reports/**",
    "site/**",
    "coverage/**",
    "htmlcov/**",
    ".git/**",
    "target/**",
    ".gradle/**",
    ".next/**",
    ".nuxt/**",
)


def _list_git_files(project_root: Path, args: list[str]) -> set[str]:
    try:
        completed = subprocess.run(
            ["git", "-C", str(project_root), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except Exception:
        return set()
    if completed.returncode != 0:
        return set()
    return {line.strip() for line in completed.stdout.splitlines() if line.strip()}


def _effective_sensitive_ignored_patterns(config: CodeGaugeConfig) -> tuple[str, ...]:
    add = tuple(pattern for pattern in config.secrets.ignored_sensitive_patterns_add if isinstance(pattern, str) and pattern)
    remove = {pattern for pattern in config.secrets.ignored_sensitive_patterns_remove if isinstance(pattern, str) and pattern}
    merged = [pattern for pattern in SENSITIVE_IGNORED_PATTERNS if pattern not in remove]
    for pattern in add:
        if pattern not in merged:
            merged.append(pattern)
    return tuple(merged)


def _build_scan_scope(project_root: Path, excludes: list[str], config: CodeGaugeConfig) -> dict[str, object]:
    tracked_files = _list_git_files(project_root, ["ls-files"])
    ignored_files = _list_git_files(project_root, ["ls-files", "--others", "-i", "--exclude-standard"])
    deny = set(excludes) | set(EXCLUDED_JUNK_PATTERNS)
    effective_patterns = _effective_sensitive_ignored_patterns(config)

    tracked_scannable = sorted(rel for rel in tracked_files if not any(fnmatch.fnmatch(rel, pattern) for pattern in deny))
    ignored_sensitive = sorted(
        rel
        for rel in ignored_files
        if any(fnmatch.fnmatch(Path(rel).name, pattern) or fnmatch.fnmatch(rel, pattern) for pattern in effective_patterns)
        and not any(fnmatch.fnmatch(rel, pattern) for pattern in deny)
    )

    docs_count = sum(1 for rel in tracked_scannable if rel.startswith("docs/") or rel.startswith("documentation/") or rel.startswith("Documentation/"))
    fixtures_count = sum(1 for rel in tracked_scannable if "/fixtures/" in f"/{rel}" or rel.startswith("fixtures/"))
    third_party_count = sum(
        1
        for rel in tracked_scannable
        if any(part in rel.lower() for part in ("node_modules/", "vendor/", "third_party/"))
    )
    generated_count = sum(
        1
        for rel in tracked_scannable
        if any(part in rel.lower() for part in ("/generated/", "/dist/", "/build/", "_generated"))
    )
    excluded_count = sum(1 for rel in [*tracked_files, *ignored_files] if any(fnmatch.fnmatch(rel, p) for p in deny))

    return {
        "zones": {
            InventoryZone.TRACKED.value: tracked_scannable,
            InventoryZone.IGNORED_SENSITIVE.value: ignored_sensitive,
        },
        "ignored_sensitive_present": len(ignored_sensitive),
        "ignored_sensitive_patterns": len(effective_patterns),
        "ignored_sensitive_patterns_effective": list(effective_patterns),
        "zone_counts": {
            "tracked": len(tracked_scannable),
            "ignored_sensitive": len(ignored_sensitive),
            "docs": docs_count,
            "fixtures": fixtures_count,
            "third_party": third_party_count,
            "generated": generated_count,
            "excluded": excluded_count,
        },
    }


def _resolve_policy(project: Project) -> tuple[str, set[str], dict[str, str]]:
    disabled: dict[str, str] = {}
    enabled: set[str] = set()
    language = str(project.metadata.get("language", "python")) if isinstance(project.metadata, dict) else "python"
    framework = str(project.metadata.get("python_framework", "generic"))
    if language == "python" and framework == "django":
        enabled.update({"django_check_deploy", "django_settings_scan", "django_template_scan", "django_orm_health"})
    elif language == "python" and framework in {"fastapi", "flask", "generic"}:
        disabled.update(
            {
                "django_check_deploy": DisabledReason.framework_incompatible,
                "django_settings_scan": DisabledReason.framework_incompatible,
                "django_template_scan": DisabledReason.framework_incompatible,
                "django_orm_health": DisabledReason.framework_incompatible,
            }
        )
    elif language != "python":
        disabled.update(
            {
                "django_check_deploy": DisabledReason.framework_incompatible,
                "django_settings_scan": DisabledReason.framework_incompatible,
                "django_template_scan": DisabledReason.framework_incompatible,
                "django_orm_health": DisabledReason.framework_incompatible,
            }
        )
    return framework if language == "python" else language, enabled, disabled


def load_resolved_config(project_path: Path) -> CodeGaugeConfig:
    scanner_registry = ScannerRegistry([])
    register_builtin_scanners(scanner_registry)
    known_scanners = {scanner.scanner_name for scanner in scanner_registry.scanners}
    return load_config(project_path=project_path, known_scanners=known_scanners)


def load_resolved_config_with_overrides(project_path: Path, *, report_root: Path | None = None, state_root: Path | None = None, open_report: bool | None = None) -> CodeGaugeConfig:
    scanner_registry = ScannerRegistry([])
    register_builtin_scanners(scanner_registry)
    known_scanners = {scanner.scanner_name for scanner in scanner_registry.scanners}
    overrides: dict[str, object] = {}
    if report_root is not None:
        overrides["report_root"] = str(report_root)
    if state_root is not None:
        overrides["state_root"] = str(state_root)
    if open_report is not None:
        overrides["open_report"] = open_report
    return load_config(project_path=project_path, known_scanners=known_scanners, overrides=overrides)


def build_scan_services(path: Path) -> ScanApplicationServices:
    project_path = path.expanduser().resolve()
    config = load_resolved_config(project_path)
    project = ProjectDiscoveryService(ProfileRegistry.with_builtins()).discover(project_path)
    framework, policy_enabled, policy_disabled = _resolve_policy(project)
    inventory = _build_inventory(project_path, config.exclude)
    scan_scope = _build_scan_scope(project_path, config.exclude, config)
    metadata = dict(project.metadata)
    metadata["inventory"] = inventory
    metadata["scan_scope"] = scan_scope
    metadata["policy_resolution"] = {
        "framework": framework,
        "language": str(metadata.get("language", "python")),
        "framework_confidence": float(metadata.get("python_runtime", {}).get("framework_confidence", 0.4))
        if isinstance(metadata.get("python_runtime"), dict)
        else 0.4,
        "enabled": sorted(policy_enabled),
        "disabled": {k: str(v) for k, v in sorted(policy_disabled.items())},
    }
    project = project.model_copy(update={"config": config.model_dump(mode="json"), "metadata": metadata}, deep=True)

    scanner_registry = ScannerRegistry([])
    register_builtin_scanners(scanner_registry)
    scanner_registry = _apply_scanner_config(scanner_registry, config)
    if policy_disabled:
        scanner_registry = ScannerRegistry(
            scanner_registry.scanners,
            enabled_names=scanner_registry.enabled_names,
            disabled_names=scanner_registry.disabled_names.union(policy_disabled.keys()),
        )

    parser_registry = ParserRegistry()
    register_builtin_parsers(parser_registry)

    orchestrator = ScanOrchestrator(scanner_registry, parser_registry)
    return ScanApplicationServices(
        project_path=project_path,
        project=project,
        config=config,
        scanner_registry=scanner_registry,
        parser_registry=parser_registry,
        orchestrator=orchestrator,
    )


def build_scan_services_with_config(path: Path, config: CodeGaugeConfig) -> ScanApplicationServices:
    project_path = path.expanduser().resolve()
    project = ProjectDiscoveryService(ProfileRegistry.with_builtins()).discover(project_path)
    framework, policy_enabled, policy_disabled = _resolve_policy(project)
    inventory = _build_inventory(project_path, config.exclude)
    scan_scope = _build_scan_scope(project_path, config.exclude, config)
    metadata = dict(project.metadata)
    metadata["inventory"] = inventory
    metadata["scan_scope"] = scan_scope
    metadata["policy_resolution"] = {
        "framework": framework,
        "language": str(metadata.get("language", "python")),
        "framework_confidence": float(metadata.get("python_runtime", {}).get("framework_confidence", 0.4))
        if isinstance(metadata.get("python_runtime"), dict)
        else 0.4,
        "enabled": sorted(policy_enabled),
        "disabled": {k: str(v) for k, v in sorted(policy_disabled.items())},
    }
    project = project.model_copy(update={"config": config.model_dump(mode="json"), "metadata": metadata}, deep=True)

    scanner_registry = ScannerRegistry([])
    register_builtin_scanners(scanner_registry)
    scanner_registry = _apply_scanner_config(scanner_registry, config)
    if policy_disabled:
        scanner_registry = ScannerRegistry(
            scanner_registry.scanners,
            enabled_names=scanner_registry.enabled_names,
            disabled_names=scanner_registry.disabled_names.union(policy_disabled.keys()),
        )

    parser_registry = ParserRegistry()
    register_builtin_parsers(parser_registry)
    orchestrator = ScanOrchestrator(scanner_registry, parser_registry)
    return ScanApplicationServices(
        project_path=project_path,
        project=project,
        config=config,
        scanner_registry=scanner_registry,
        parser_registry=parser_registry,
        orchestrator=orchestrator,
    )
