from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import fnmatch

from ..constants import DisabledReason
from ..config import CodeGaugeConfig, load_config
from ..domain.models import Project
from ..parsers import (
    BanditParser,
    CheckstyleParser,
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
    JaCoCoParser,
    JSCoverageParser,
    NPMAuditParser,
    OpenGrepInfraParser,
    OpenGrepJavaParser,
    OpenGrepJSParser,
    OpenGrepParser,
    PMDParser,
    PyrightParser,
    QuadletScanParser,
    RadonParser,
    ReverseProxyScanParser,
    RuffParser,
    ShellCheckParser,
    SpotBugsParser,
    TerraformScanParser,
    TypeScriptDiagnosticsParser,
    VultureParser,
)
from ..scanners import (
    BanditScanner,
    CheckstyleScanner,
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
    JaCoCoScanner,
    JSCoverageScanner,
    NpmAuditScanner,
    OpenGrepInfraScanner,
    OpenGrepJavaScanner,
    OpenGrepJSScanner,
    OpenGrepScanner,
    PMDScanner,
    PyrightScanner,
    QuadletScanScanner,
    RadonScanner,
    ReverseProxyScanScanner,
    RuffScanner,
    ShellCheckScanner,
    SpotBugsScanner,
    TerraformScanScanner,
    TypeScriptDiagnosticsScanner,
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


def register_builtin_parsers(registry: ParserRegistry) -> None:
    registry.register(RuffParser())
    registry.register(PyrightParser())
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


def _resolve_policy(project: Project) -> tuple[str, set[str], dict[str, str]]:
    disabled: dict[str, str] = {}
    enabled: set[str] = set()
    framework = str(project.metadata.get("python_framework", "generic"))
    if framework == "django":
        enabled.update({"django_check_deploy", "django_settings_scan", "django_template_scan", "django_orm_health"})
    elif framework in {"fastapi", "flask", "generic"}:
        disabled.update(
            {
                "django_check_deploy": DisabledReason.framework_incompatible,
                "django_settings_scan": DisabledReason.framework_incompatible,
                "django_template_scan": DisabledReason.framework_incompatible,
                "django_orm_health": DisabledReason.framework_incompatible,
            }
        )
    return framework, enabled, disabled


def load_resolved_config(project_path: Path) -> CodeGaugeConfig:
    scanner_registry = ScannerRegistry([])
    register_builtin_scanners(scanner_registry)
    known_scanners = {scanner.scanner_name for scanner in scanner_registry.scanners}
    return load_config(project_path=project_path, known_scanners=known_scanners)


def build_scan_services(path: Path) -> ScanApplicationServices:
    project_path = path.expanduser().resolve()
    config = load_resolved_config(project_path)
    project = ProjectDiscoveryService(ProfileRegistry.with_builtins()).discover(project_path)
    framework, policy_enabled, policy_disabled = _resolve_policy(project)
    inventory = _build_inventory(project_path, config.exclude)
    metadata = dict(project.metadata)
    metadata["inventory"] = inventory
    metadata["policy_resolution"] = {
        "framework": framework,
        "language": str(metadata.get("python_runtime", {}).get("language", "python"))
        if isinstance(metadata.get("python_runtime"), dict)
        else "python",
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
