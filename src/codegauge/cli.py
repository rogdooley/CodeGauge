from __future__ import annotations

import json
import os
import hashlib
import subprocess
import shutil
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

import typer

from .constants import ExitCode, InternalErrorCode, ParserErrorCode, ScannerErrorCode
from .baseline import BaselineService
from .bootstrap.factory import (
    build_scan_services_with_config,
    load_resolved_config_with_overrides,
    load_resolved_config,
    register_builtin_parsers,
    register_builtin_scanners,
)
from .config import ConfigLoadError
from .domain.models import Language, ScanSummary, ScanResultSummary
from .policy import CodeGaugePolicyEngine, PolicyStatus
from .reporting import StaticSiteBuilder
from .scoring import CodeGaugeScoringEngine
from .services.metrics import MetricsExtractor, finding_fingerprint
from .services.recommendation_engine import RecommendationEngine, strip_internal_scores
from .services.report_normalizer import (
    FINGERPRINT_VERSION,
    MESSAGE_NORMALIZER_VERSION,
    finding_sort_key,
    normalize_finding_record,
)
from .services.parser_registry import ParserRegistry
from .services.scanner_registry import ScannerRegistry
from .storage import ScanArtifactStore
from .storage import JavaBuildCacheService
from .paths import java_cache_root_for_project, open_in_browser
from .cli_handlers.scan import scan_handler
from .cli_handlers.open import open_portal_handler
from .cli_handlers.list_scanners import list_scanners_handler
from .cli_handlers.prune import prune_reports_handler
from .cli_handlers.baseline import baseline_init_handler
from .cli_handlers.formatting import render_scan_human_summary

app = typer.Typer()
baseline_app = typer.Typer()
app.add_typer(baseline_app, name="baseline")
cache_app = typer.Typer()
app.add_typer(cache_app, name="cache")
secrets_app = typer.Typer()
app.add_typer(secrets_app, name="secrets")

_PARSE_FAILURE_CODES = {
    ParserErrorCode.parse_error,
    ParserErrorCode.output_invalid,
}
_PARSER_MISSING_CODE = ParserErrorCode.parser_missing
_INVALID_PATH_CODE = ParserErrorCode.finding_path_invalid


def _atomic_write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    temp_file = Path(temp_path)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temp_file, path)
    except Exception:
        if temp_file.exists():
            temp_file.unlink()
        raise


def _collect_scalar_metrics(results) -> dict[str, object]:
    scalar: dict[str, object] = {}
    for result in results:
        payload = result.metadata.get("scalar_metrics")
        if not isinstance(payload, dict):
            continue
        for key, value in payload.items():
            scalar[key] = value
    return scalar


def _to_int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _collect_java_cache_summary(results) -> dict[str, object]:
    cached_modules = 0
    cache_hits = 0
    cache_misses = 0
    last_cache_update: str | None = None
    miss_reason_counts: dict[str, int] = {}
    tool_status: dict[str, dict[str, object]] = {}
    for result in results:
        cache_meta = result.metadata.get("cache")
        if not isinstance(cache_meta, dict):
            continue
        tool = str(cache_meta.get("tool", result.scanner_name))
        tool_entry = tool_status.setdefault(
            tool,
            {"tool": tool, "hits": 0, "misses": 0, "miss_reason_counts": {}},
        )
        cached_modules += int(cache_meta.get("cached_modules", 0) or 0)
        tool_hits = int(cache_meta.get("cache_hits", 0) or 0)
        tool_misses = int(cache_meta.get("cache_misses", 0) or 0)
        cache_hits += tool_hits
        cache_misses += tool_misses
        tool_entry["hits"] = _to_int(tool_entry.get("hits")) + tool_hits
        tool_entry["misses"] = _to_int(tool_entry.get("misses")) + tool_misses
        reasons = cache_meta.get("miss_reason_counts")
        if isinstance(reasons, dict):
            reason_bucket = tool_entry["miss_reason_counts"]
            if isinstance(reason_bucket, dict):
                for reason, count in reasons.items():
                    if not isinstance(count, int):
                        continue
                    reason_bucket[reason] = int(reason_bucket.get(reason, 0)) + count
                    miss_reason_counts[reason] = miss_reason_counts.get(reason, 0) + count
        update = cache_meta.get("last_cache_update")
        if isinstance(update, str) and update:
            if last_cache_update is None or update > last_cache_update:
                last_cache_update = update
    hit_rate = round((cache_hits / (cache_hits + cache_misses)) * 100.0, 2) if (cache_hits + cache_misses) else None
    return {
        "cached_modules": cached_modules,
        "cache_hits": cache_hits,
        "cache_misses": cache_misses,
        "hit_rate_percent": hit_rate,
        "miss_reason_counts": dict(sorted(miss_reason_counts.items())),
        "tools": sorted(tool_status.values(), key=lambda item: str(item["tool"])),
        "last_cache_update": last_cache_update,
    }


def _summary_exit_code(results_payload, policy_status: PolicyStatus, *, policy_gate: bool) -> int:
    scanner_failure = any(
        row.error_code
        in {
            ScannerErrorCode.contract_violation,
            ScannerErrorCode.binary_missing,
            ScannerErrorCode.config_error,
            ScannerErrorCode.nonzero_exit,
            ScannerErrorCode.timeout,
        }
        for row in results_payload
    )
    parser_failure = any(
        row.error_code in {ParserErrorCode.parser_missing, ParserErrorCode.parse_error, ParserErrorCode.output_invalid}
        for row in results_payload
    ) or any(int(row.metadata.get("invalid_finding_count", 0) or 0) > 0 for row in results_payload)
    if scanner_failure:
        return int(ExitCode.scanner_failure)
    if parser_failure:
        return int(ExitCode.parser_failure)
    if policy_gate:
        if policy_status == PolicyStatus.pass_:
            return int(ExitCode.success)
        if policy_status == PolicyStatus.warn:
            return int(ExitCode.policy_warning)
        if policy_status == PolicyStatus.fail:
            return int(ExitCode.policy_fail)
    return int(ExitCode.success)


def _compact_scanner_raw_output(result) -> dict[str, object]:
    base = {
        "command": result.metadata.get("command"),
        "exit_code": result.metadata.get("exit_code"),
        "error_code": result.error_code,
        "duration_ms": result.duration_ms,
    }
    if result.scanner_name in {"opengrep", "opengrep_java"}:
        samples: list[dict[str, object]] = []
        for finding in result.findings[:25]:
            samples.append(
                {
                    "rule_id": finding.rule_id,
                    "file": finding.file.as_posix(),
                    "line": finding.line,
                    "message": finding.message,
                }
            )
        base["finding_count"] = len(result.findings)
        base["rules"] = sorted({finding.rule_id for finding in result.findings})
        base["files"] = sorted({finding.file.as_posix() for finding in result.findings})
        base["sample_messages"] = samples
        base["stderr"] = result.metadata.get("stderr")
        return base

    base["stdout"] = result.metadata.get("stdout")
    base["stderr"] = result.metadata.get("stderr")
    return base


def _to_scan_summary(
    project_name: str,
    duration_ms: float,
    results,
    *,
    project_metadata: dict[str, object] | None = None,
    verbose: bool,
    score_card: dict | None = None,
    policy: dict | None = None,
) -> ScanSummary:
    successful = sum(1 for result in results if result.success)
    failed = len(results) - successful
    invalid_findings = 0
    invalid_paths = 0
    parse_failures = 0
    parser_missing = 0
    scanner_failures = 0
    summaries: list[ScanResultSummary] = []
    for result in results:
        invalid_count = int(result.metadata.get("invalid_finding_count", 0) or 0)
        invalid_findings += invalid_count
        if result.error_code == _INVALID_PATH_CODE:
            invalid_paths += invalid_count if invalid_count else 1
        if result.error_code == _PARSER_MISSING_CODE:
            parser_missing += 1
        elif result.error_code in _PARSE_FAILURE_CODES:
            parse_failures += 1
        elif not result.success and result.error_code != _INVALID_PATH_CODE:
            scanner_failures += 1
        summaries.append(
            ScanResultSummary(
                scanner_name=result.scanner_name,
                success=result.success,
                error_code=result.error_code,
                finding_count=len(result.findings),
                duration_ms=result.duration_ms,
                metadata=result.metadata if verbose else None,
                stdout=result.metadata.get("stdout") if verbose else None,
                stderr=result.metadata.get("stderr") if verbose else None,
                command=result.metadata.get("command") if verbose else None,
                exit_code=result.metadata.get("exit_code") if verbose else None,
            )
        )
    return ScanSummary(
        project=project_name,
        project_metadata=project_metadata,
        duration_ms=duration_ms,
        scanner_count=len(results),
        successful_scanners=successful,
        failed_scanners=failed,
        finding_count=sum(len(result.findings) for result in results),
        invalid_findings=invalid_findings,
        invalid_paths=invalid_paths,
        parse_failures=parse_failures,
        parser_missing=parser_missing,
        scanner_failures=scanner_failures,
        score_card=score_card,
        policy=policy,
        results=summaries,
    )


def _git_history_scan_gate(project_path: Path, *, commit_limit: int, size_limit_mb: int) -> dict[str, object]:
    try:
        commit_run = subprocess.run(
            ["git", "-C", str(project_path), "rev-list", "--count", "--all"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        commit_count = int((commit_run.stdout or "0").strip() or "0") if commit_run.returncode == 0 else 0
    except Exception:
        commit_count = 0

    size_bytes = 0
    try:
        for path in project_path.rglob("*"):
            if path.is_file():
                size_bytes += path.stat().st_size
    except Exception:
        size_bytes = 0
    size_mb = int(size_bytes / (1024 * 1024))

    if commit_count > commit_limit:
        return {
            "allowed": False,
            "reason": "commit_limit_exceeded",
            "commit_count": commit_count,
            "commit_limit": commit_limit,
            "repo_size_mb": size_mb,
            "size_limit_mb": size_limit_mb,
        }
    if size_mb > size_limit_mb:
        return {
            "allowed": False,
            "reason": "size_limit_exceeded",
            "commit_count": commit_count,
            "commit_limit": commit_limit,
            "repo_size_mb": size_mb,
            "size_limit_mb": size_limit_mb,
        }
    return {
        "allowed": True,
        "reason": "within_limits",
        "commit_count": commit_count,
        "commit_limit": commit_limit,
        "repo_size_mb": size_mb,
        "size_limit_mb": size_limit_mb,
    }


@app.command()
def scan(
    path: Path,
    json_output: bool = typer.Option(False, "--json"),
    verbose: bool = typer.Option(False, "--verbose"),
    report_root: Path | None = typer.Option(None, "--report-root"),
    state_root: Path | None = typer.Option(None, "--state-root"),
    open_report: bool | None = typer.Option(None, "--open/--no-open"),
    fail_on_policy: bool = typer.Option(
        False,
        "--fail-on-policy",
        help=(
            "Set process exit code from policy status when scan succeeds: pass=0, warn=1, fail=2. "
            "Execution errors use fixed codes: config=3, scanner=4, parser=5, internal=6, interrupted=7."
        ),
    ),
    capture_full_raw: bool = typer.Option(
        False,
        "--capture-full-raw",
        help="Capture full unredacted raw payload (requires payload.capture_full_raw=true in config).",
    ),
    ) -> None:
    scan_handler(
        path=path,
        json_output=json_output,
        verbose=verbose,
        report_root=report_root,
        state_root=state_root,
        open_report=open_report,
        fail_on_policy=fail_on_policy,
        capture_full_raw=capture_full_raw,
        collect_scalar_metrics=_collect_scalar_metrics,
        collect_java_cache_summary=_collect_java_cache_summary,
        to_scan_summary=_to_scan_summary,
        compact_scanner_raw_output=_compact_scanner_raw_output,
        summary_exit_code=_summary_exit_code,
        render_scan_human_summary=render_scan_human_summary,
        load_config_fn=load_resolved_config_with_overrides,
        build_services_fn=build_scan_services_with_config,
        open_browser_fn=open_in_browser,
    )


def _build_secrets_services(path: Path, config, *, include_history: bool, force_history: bool, include_fixtures: bool):
    if not config.secrets.enabled:
        secret_scanners = []
    else:
        secret_scanners = ["gitleaks", "trufflehog", "secrets_heuristic"]
    history_gate = {
        "requested": include_history,
        "enabled": False,
        "skipped": False,
        "reason": "not_requested",
        "history_scan_status": "never_scanned",
        "history_last_scanned": None,
        "history_scan_age_days": None,
        "history_scan_stale": False,
    }
    if include_history:
        gate = _git_history_scan_gate(
            path,
            commit_limit=config.secrets.history_commit_limit,
            size_limit_mb=config.secrets.history_size_limit_mb,
        )
        if force_history or config.secrets.history_scan_enabled or bool(gate.get("allowed")):
            secret_scanners.append("git_history_secrets")
            history_gate = {
                "requested": True,
                "enabled": True,
                "skipped": False,
                "reason": "forced" if force_history else "enabled",
                "history_scan_status": "fresh",
                "history_last_scanned": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "history_scan_age_days": 0,
                "history_scan_stale": False,
                **gate,
            }
        else:
            history_gate = {
                "requested": True,
                "enabled": False,
                "skipped": True,
                "reason": str(gate.get("reason") or "threshold_exceeded"),
                "history_scan_status": "stale",
                "history_last_scanned": None,
                "history_scan_age_days": None,
                "history_scan_stale": True,
                **gate,
            }
    fixture_default = bool(config.secrets.exclude_fixtures)
    effective_exclude_fixtures = fixture_default and not include_fixtures
    fixture_excludes = ["tests/fixtures/**", "fixtures/**", "docs/examples/**"] if effective_exclude_fixtures else []
    unavailable_scanners: list[dict[str, str]] = []
    for scanner_name, install_hint in (("gitleaks", "brew install gitleaks"), ("trufflehog", "brew install trufflehog")):
        if scanner_name in secret_scanners and shutil.which(scanner_name) is None:
            unavailable_scanners.append({"scanner": scanner_name, "install_hint": install_hint})

    unavailable_names = {row["scanner"] for row in unavailable_scanners}
    updated = config.model_copy(
        update={
            "enabled_scanners": [name for name in secret_scanners if name not in unavailable_names],
            "exclude": list(config.exclude) + fixture_excludes,
            "disabled_scanners": [
                name
                for name in config.disabled_scanners
                if name not in {"gitleaks", "trufflehog", "secrets_heuristic", "git_history_secrets"}
            ] + sorted(unavailable_names),
        }
    )
    services = build_scan_services_with_config(path, updated)
    metadata = dict(services.project.metadata) if isinstance(services.project.metadata, dict) else {}
    scope_metadata = metadata.get("scan_scope", {}) if isinstance(metadata.get("scan_scope"), dict) else {}
    language_hints = list(services.project.language_hints)
    if Language.general not in language_hints:
        language_hints.append(Language.general)
    project = services.project.model_copy(
        update={
            "language_hints": language_hints,
            "metadata": {
                **metadata,
                "history_scan_gate": history_gate,
                "secrets_fixture_excludes": fixture_excludes,
                "secret_scanner_unavailable": unavailable_scanners,
                "ignored_sensitive_present": int(scope_metadata.get("ignored_sensitive_present", 0) or 0),
                "ignored_sensitive_patterns": int(scope_metadata.get("ignored_sensitive_patterns", 0) or 0),
            }
        },
        deep=True,
    )
    return services.__class__(
        project_path=services.project_path,
        project=project,
        config=services.config,
        scanner_registry=services.scanner_registry,
        parser_registry=services.parser_registry,
        orchestrator=services.orchestrator,
    )


@secrets_app.command("scan")
def secrets_scan(
    path: Path,
    history: bool = typer.Option(False, "--history"),
    force_history: bool = typer.Option(False, "--force-history"),
    include_fixtures: bool = typer.Option(False, "--include-fixtures"),
    json_output: bool = typer.Option(False, "--json"),
    report_root: Path | None = typer.Option(None, "--report-root"),
    state_root: Path | None = typer.Option(None, "--state-root"),
    fail_on_secret: bool | None = typer.Option(None, "--fail-on-secret/--no-fail-on-secret"),
) -> None:
    resolved_path = path.expanduser().resolve()
    resolved_config = load_resolved_config_with_overrides(
        resolved_path,
        report_root=report_root,
        state_root=state_root,
        open_report=None,
    )
    effective_fail_on_secret = bool(resolved_config.secrets.fail_on_secret if fail_on_secret is None else fail_on_secret)
    scan_handler(
        path=path,
        json_output=json_output,
        verbose=False,
        report_root=report_root,
        state_root=state_root,
        open_report=None,
        fail_on_policy=effective_fail_on_secret,
        capture_full_raw=False,
        collect_scalar_metrics=_collect_scalar_metrics,
        collect_java_cache_summary=_collect_java_cache_summary,
        to_scan_summary=_to_scan_summary,
        compact_scanner_raw_output=_compact_scanner_raw_output,
        summary_exit_code=_summary_exit_code,
        render_scan_human_summary=render_scan_human_summary,
        load_config_fn=load_resolved_config_with_overrides,
        build_services_fn=lambda p, c: _build_secrets_services(
            p,
            c,
            include_history=history,
            force_history=force_history,
            include_fixtures=include_fixtures,
        ),
        open_browser_fn=open_in_browser,
    )


@app.command("build-site")
def build_site(
    path: Path = typer.Argument(Path.cwd()),
    report_root: Path | None = typer.Option(None, "--report-root"),
    state_root: Path | None = typer.Option(None, "--state-root"),
    open_report: bool | None = typer.Option(None, "--open/--no-open"),
) -> None:
    try:
        resolved_path = path.expanduser().resolve()
        config = load_resolved_config_with_overrides(
            resolved_path,
            report_root=report_root,
            state_root=state_root,
            open_report=open_report,
        )
        builder = StaticSiteBuilder(report_root=config.report_root)
        output = builder.build()
    except ConfigLoadError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except Exception as exc:
        typer.echo(f"site build failed: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.internal_error)) from exc

    typer.echo(f"Built site for {output['project_count']} projects at {output['output_dir']}")
    should_open = bool(open_report if open_report is not None else config.open_report)
    if should_open:
        opened, message = open_in_browser(config.report_root / "index.html")
        if opened:
            typer.echo(message)
        else:
            typer.echo(f"Info: {message}", err=True)


@app.command("prune-reports")
def prune_reports(
    path: Path = typer.Argument(Path.cwd()),
    keep: int | None = typer.Option(None, "--keep", min=1),
    days: int | None = typer.Option(None, "--days", min=1),
    project: list[str] | None = typer.Option(None, "--project"),
    report_root: Path | None = typer.Option(None, "--report-root"),
    state_root: Path | None = typer.Option(None, "--state-root"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    prune_reports_handler(
        path=path,
        keep=keep,
        days=days,
        project=project,
        report_root=report_root,
        state_root=state_root,
        dry_run=dry_run,
    )


@app.command()
def list_scanners(json_output: bool = typer.Option(False, "--json")) -> None:
    list_scanners_handler(json_output=json_output)


@app.command()
def show_config(path: Path = typer.Argument(Path.cwd()), human: bool = False) -> None:
    try:
        config = load_resolved_config(path.expanduser().resolve())
    except ConfigLoadError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if human:
        typer.echo(f"report_root: {config.report_root}")
        typer.echo(f"state_root: {config.state_root}")
        typer.echo(f"open_report: {config.open_report}")
        typer.echo(f"default_timeout_seconds: {config.default_timeout_seconds}")
        typer.echo(f"enabled_scanners: {', '.join(config.enabled_scanners) or '(all)'}")
        typer.echo(f"disabled_scanners: {', '.join(config.disabled_scanners) or '(none)'}")
        typer.echo(f"exclude: {', '.join(config.exclude) or '(none)'}")
        typer.echo(f"thresholds: {json.dumps(config.thresholds.model_dump(), indent=2, sort_keys=True)}")
        typer.echo(
            f"scanners: {json.dumps({k: v.model_dump() for k, v in config.scanners.items()}, indent=2, sort_keys=True)}"
        )
        return

    typer.echo(json.dumps(config.model_dump(mode="json"), indent=2, sort_keys=True))


@cache_app.command("status")
def cache_status(
    project_path: Path = typer.Argument(Path.cwd()),
    state_root: Path | None = typer.Option(None, "--state-root"),
    module: str | None = typer.Option(None, "--module"),
    tool: str | None = typer.Option(None, "--tool"),
    json_output: bool = typer.Option(True, "--json/--human"),
) -> None:
    project_root = project_path.expanduser().resolve()
    config = load_resolved_config_with_overrides(project_root, state_root=state_root)
    config.state_root.mkdir(parents=True, exist_ok=True)
    service = JavaBuildCacheService(project_root, cache_root=java_cache_root_for_project(config.state_root, project_root))
    status = service.status()
    if module is not None:
        filtered = [entry for entry in status["modules"] if entry["module_name"] == module]
        if not filtered:
            typer.echo(f"Module not found: {module}", err=True)
            raise typer.Exit(code=3)
        status["modules"] = filtered
    if tool is not None:
        known_tools = service.known_tools()
        if tool not in known_tools:
            typer.echo(f"Tool not found in cache: {tool}", err=True)
            raise typer.Exit(code=3)
        for entry in status["modules"]:
            entry["tools"] = [row for row in entry.get("tools", []) if row.get("tool") == tool]
    if json_output:
        typer.echo(json.dumps(status, indent=2, sort_keys=True))
        return
    typer.echo(f"Project: {status['project']}")
    totals = status.get("totals", {})
    typer.echo(
        f"Cache totals: hits={totals.get('hits', 0)} misses={totals.get('misses', 0)} "
        f"hit_rate={totals.get('hit_rate_percent', 'n/a')}"
    )
    for entry in status.get("modules", []):
        typer.echo(f"Module: {entry['module_name']} ({entry['module_path']})")
        for row in entry.get("tools", []):
            typer.echo(
                f"- {row.get('tool')} status={row.get('last_status')} "
                f"reasons={','.join(row.get('last_reasons', [])) or '-'}"
            )


@cache_app.command("clear")
def cache_clear(
    project_path: Path = typer.Argument(Path.cwd()),
    state_root: Path | None = typer.Option(None, "--state-root"),
    module: str | None = typer.Option(None, "--module"),
    tool: str | None = typer.Option(None, "--tool"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    project_root = project_path.expanduser().resolve()
    config = load_resolved_config_with_overrides(project_root, state_root=state_root)
    config.state_root.mkdir(parents=True, exist_ok=True)
    service = JavaBuildCacheService(project_root, cache_root=java_cache_root_for_project(config.state_root, project_root))
    if module is not None:
        module_names = {entry["module_name"] for entry in service.status()["modules"]}
        if module not in module_names:
            typer.echo(f"Module not found: {module}", err=True)
            raise typer.Exit(code=3)
    if tool is not None:
        known_tools = service.known_tools()
        if tool not in known_tools:
            typer.echo(f"Tool not found in cache: {tool}", err=True)
            raise typer.Exit(code=3)
    result = service.clear(module_name=module, tool=tool, dry_run=dry_run)
    typer.echo(json.dumps(result, indent=2, sort_keys=True))


@cache_app.command("prune")
def cache_prune(
    project_path: Path = typer.Argument(Path.cwd()),
    state_root: Path | None = typer.Option(None, "--state-root"),
    days: int = typer.Option(30, "--days", min=1),
    max_history: int = typer.Option(10, "--max-history", min=1),
    project: list[str] | None = typer.Option(None, "--project"),
    module: str | None = typer.Option(None, "--module"),
    tool: str | None = typer.Option(None, "--tool"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    project_root = project_path.expanduser().resolve()
    config = load_resolved_config_with_overrides(project_root, state_root=state_root)
    config.state_root.mkdir(parents=True, exist_ok=True)
    service = JavaBuildCacheService(project_root, cache_root=java_cache_root_for_project(config.state_root, project_root))
    status = service.status()
    current_project = str(status.get("project", project_root.name))

    if project:
        unique_requested: list[str] = []
        seen: set[str] = set()
        for name in project:
            if name in seen:
                continue
            seen.add(name)
            unique_requested.append(name)
        missing = [name for name in unique_requested if name != current_project]
        if missing:
            typer.echo(f"Project(s) not found for cache root '{current_project}': {', '.join(missing)}", err=True)
            raise typer.Exit(code=3)

    module_names = {entry["module_name"] for entry in status.get("modules", [])}
    if module is not None and module not in module_names:
        typer.echo(f"Module not found: {module}", err=True)
        raise typer.Exit(code=3)
    if tool is not None:
        known_tools = service.known_tools()
        if tool not in known_tools:
            typer.echo(f"Tool not found in cache: {tool}", err=True)
            raise typer.Exit(code=3)

    result = service.prune(days=days, max_history=max_history, module_name=module, tool=tool, dry_run=dry_run)
    gib = float(result.get("space_reclaimed_bytes", 0) or 0) / (1024 * 1024 * 1024)
    typer.echo(f"Cache entries removed: {int(result.get('cache_entries_removed', 0))}")
    typer.echo(f"History entries pruned: {int(result.get('history_entries_pruned', 0))}")
    typer.echo(f"Artifacts removed: {int(result.get('artifacts_removed', 0))}")
    typer.echo(f"Abandoned module caches removed: {int(result.get('abandoned_module_caches_removed', 0))}")
    typer.echo(f"Space reclaimed: {gib:.2f} GB")
    typer.echo(f"Dry run: {'yes' if dry_run else 'no'}")


@baseline_app.command("init")
def baseline_init(
    project_path: Path,
    report_root: Path | None = typer.Option(None, "--report-root"),
    state_root: Path | None = typer.Option(None, "--state-root"),
    output: Path = typer.Option(Path("baseline.json"), "--output"),
    owner: str | None = typer.Option(None, "--owner"),
    note: str | None = typer.Option(None, "--note"),
    expires_days: int | None = typer.Option(None, "--expires-days", min=1),
    dry_run: bool = typer.Option(False, "--dry-run"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    baseline_init_handler(
        project_path=project_path,
        report_root=report_root,
        state_root=state_root,
        output=output,
        owner=owner,
        note=note,
        expires_days=expires_days,
        dry_run=dry_run,
        force=force,
        atomic_write_json=_atomic_write_json,
        to_int=_to_int,
        load_config_fn=load_resolved_config_with_overrides,
        build_services_fn=build_scan_services_with_config,
    )


@app.command("open")
def open_portal(
    path: Path = typer.Argument(Path.cwd()),
    report_root: Path | None = typer.Option(None, "--report-root"),
    state_root: Path | None = typer.Option(None, "--state-root"),
) -> None:
    open_portal_handler(
        path=path,
        report_root=report_root,
        state_root=state_root,
        load_config_fn=load_resolved_config_with_overrides,
        open_browser_fn=open_in_browser,
    )
