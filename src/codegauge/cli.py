from __future__ import annotations

import json
import os
import hashlib
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

import typer

from .baseline import BaselineService
from .bootstrap.factory import (
    build_scan_services,
    load_resolved_config,
    register_builtin_parsers,
    register_builtin_scanners,
)
from .config import ConfigLoadError
from .domain.models import ScanSummary, ScanResultSummary
from .policy import CodeGaugePolicyEngine, PolicyStatus
from .reporting import StaticSiteBuilder
from .scoring import CodeGaugeScoringEngine
from .services.metrics import MetricsExtractor, finding_fingerprint
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

app = typer.Typer()
baseline_app = typer.Typer()
app.add_typer(baseline_app, name="baseline")
cache_app = typer.Typer()
app.add_typer(cache_app, name="cache")

_PARSE_FAILURE_CODES = {
    "scanner_parse_error",
    "scanner_output_invalid",
}
_PARSER_MISSING_CODE = "scanner_parser_missing"
_INVALID_PATH_CODE = "finding_path_invalid"


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
        tool_entry["hits"] = int(tool_entry["hits"]) + tool_hits
        tool_entry["misses"] = int(tool_entry["misses"]) + tool_misses
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


@app.command()
def scan(
    path: Path,
    json_output: bool = typer.Option(False, "--json"),
    verbose: bool = typer.Option(False, "--verbose"),
    fail_on_policy: bool = typer.Option(
        False,
        "--fail-on-policy",
        help="Set process exit code from policy status: pass=0, warn=1, fail=2, internal errors=3.",
    ),
    capture_full_raw: bool = typer.Option(
        False,
        "--capture-full-raw",
        help="Capture full unredacted raw payload (requires payload.capture_full_raw=true in config).",
    ),
) -> None:
    try:
        services = build_scan_services(path)
    except ConfigLoadError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        typer.echo(f"scan execution failed: {exc}", err=True)
        raise typer.Exit(code=3) from exc
    try:
        project = services.project
        start = perf_counter()
        results = services.orchestrator.run(project)
        if not results:
            typer.echo(
                f"scan execution failed: no scanners resolved for project '{project.name}'. "
                "Run from a project root or adjust enabled_scanners/config.",
                err=True,
            )
            raise typer.Exit(code=3)
        duration_ms = (perf_counter() - start) * 1000
        metrics_extractor = MetricsExtractor()
        deduped_results = metrics_extractor.dedupe_scan_results(results)
        baseline_service = BaselineService()
        baseline = baseline_service.load(project.path)
        baseline_application = baseline_service.apply(deduped_results, baseline)
        scoring_engine = CodeGaugeScoringEngine()
        policy_engine = CodeGaugePolicyEngine()
        metrics = metrics_extractor.extract_from_scan_results(
            baseline_application.filtered_results,
            dedupe=False,
        )
        score_card = scoring_engine.score(metrics)
        score_payload = score_card.model_dump(mode="json")
        score_payload["scalar_metrics"] = _collect_scalar_metrics(results)
        score_payload["measured_categories"] = sorted({metric.category.value for metric in metrics})
        score_payload["dedupe"] = metrics_extractor.last_duplicate_metadata
        score_payload["baseline"] = baseline_application.stats.model_dump(mode="json")
        score_payload["java_cache"] = _collect_java_cache_summary(results)

        pre_policy_summary = _to_scan_summary(
            project.name,
            duration_ms,
            results,
            project_metadata=dict(project.metadata),
            verbose=verbose,
            score_card=score_payload,
        )
        policy = policy_engine.evaluate(
            score_card=score_card,
            metrics=metrics,
            scanner_failures=pre_policy_summary.scanner_failures,
            parser_missing=pre_policy_summary.parser_missing,
            invalid_findings=pre_policy_summary.invalid_findings,
            invalid_paths=pre_policy_summary.invalid_paths,
            baseline_expired_entries=baseline_application.stats.expired_entries,
            baseline_missing_owner_entries=baseline_application.stats.missing_owner_entries,
            baseline_expiring_soon_entries=baseline_application.stats.expiring_soon_entries,
        )
        summary = pre_policy_summary.model_copy(update={"policy": policy.model_dump(mode="json")})
        summary_payload = summary.model_dump(mode="json")
        payload_cfg = services.config.payload
        allow_full_payload = bool(capture_full_raw and payload_cfg.capture_full_raw)
        remaining_payload_bytes = int(payload_cfg.max_bytes_global)
        findings_payload: list[dict[str, object]] = []
        for result in results:
            for finding in result.findings:
                normalized, used = normalize_finding_record(
                    finding,
                    capture_full_raw=allow_full_payload,
                    redact_payload=payload_cfg.redact,
                    max_bytes_per_finding=payload_cfg.max_bytes_per_finding,
                    remaining_global_bytes=remaining_payload_bytes,
                )
                findings_payload.append(normalized)
                remaining_payload_bytes = max(0, remaining_payload_bytes - used)
        findings_payload.sort(key=finding_sort_key)
        parser_summary_global = {
            "CODEGAUGE.PARSER.MISSING_RULE_ID": 0,
            "CODEGAUGE.PARSER.INVALID_PATH": 0,
            "CODEGAUGE.PARSER.BAD_SEVERITY": 0,
            "CODEGAUGE.PARSER.SCHEMA_ERROR": 0,
            "CODEGAUGE.PARSER.OVERSIZE_PAYLOAD": 0,
            "CODEGAUGE.PARSER.UNHANDLED": 0,
        }
        parser_summary_scanners: dict[str, dict[str, int]] = {}
        for finding in findings_payload:
            if str(finding.get("category")) != "system/parser":
                continue
            rule_id = str(finding.get("rule_id"))
            parser_summary_global.setdefault(rule_id, 0)
            parser_summary_global[rule_id] += 1
            scanner_name = str(finding.get("symbol") or "unknown")
            bucket = parser_summary_scanners.setdefault(scanner_name, dict(parser_summary_global))
            bucket.setdefault(rule_id, 0)
            bucket[rule_id] += 1
        for scanner_name, bucket in parser_summary_scanners.items():
            for key in parser_summary_global.keys():
                bucket.setdefault(key, 0)
            parser_summary_scanners[scanner_name] = dict(sorted(bucket.items()))
        inventory = dict(project.metadata.get("inventory", {})) if isinstance(project.metadata, dict) else {}
        policy_resolution = dict(project.metadata.get("policy_resolution", {})) if isinstance(project.metadata, dict) else {}
        summary_payload["schema_version"] = "2.0.0"
        summary_payload["fingerprint_version"] = FINGERPRINT_VERSION
        summary_payload["message_normalizer_version"] = MESSAGE_NORMALIZER_VERSION
        summary_payload["parser_summary"] = {
            "global": dict(sorted(parser_summary_global.items())),
            "per_scanner": dict(sorted(parser_summary_scanners.items())),
        }
        summary_payload["inventory"] = inventory
        summary_payload["policy_resolution"] = policy_resolution
        summary_payload["payload_debug_mode"] = {
            "capture_full_raw_config": payload_cfg.capture_full_raw,
            "capture_full_raw_cli": capture_full_raw,
            "capture_full_raw_effective": allow_full_payload,
            "redact_effective": False if allow_full_payload else payload_cfg.redact,
            "warning": (
                "full raw payload capture enabled; sensitive data may be present"
                if allow_full_payload
                else None
            ),
        }
        report_material = json.dumps(
            {"summary": summary_payload, "findings": findings_payload},
            sort_keys=True,
            separators=(",", ":"),
        )
        summary_payload["report_sha256"] = hashlib.sha256(report_material.encode("utf-8")).hexdigest()
        raw_outputs = {
            result.scanner_name: _compact_scanner_raw_output(result)
            for result in results
        }
        store = ScanArtifactStore(services.config.reports_dir)
        store.persist_scan_artifacts(
            project_name=project.name,
            summary=summary_payload,
            findings=findings_payload,
            score=summary.score_card or {},
            policy=summary.policy or {},
            scanner_raw_outputs=raw_outputs,
        )
    except Exception as exc:
        typer.echo(f"scan execution failed: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    if json_output:
        payload = dict(summary_payload)
        for entry in payload["results"]:
            entry.setdefault("error_code", None)
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        typer.echo(
            f"Ran {len(results)} scanners for {project.name} "
            f"({sum(1 for r in results if r.success)} succeeded, {sum(1 for r in results if not r.success)} failed)"
        )
        typer.echo(f"Overall score: {summary.score_card['overall_score']:.2f}")
        typer.echo(f"Grade: {summary.score_card['grade']}")
        typer.echo(f"Policy status: {summary.policy['status'].upper()}")
        baseline_stats = summary.score_card.get("baseline", {}) if isinstance(summary.score_card, dict) else {}
        dedupe_stats = summary.score_card.get("dedupe", {}) if isinstance(summary.score_card, dict) else {}
        typer.echo(
            "Debt summary: "
            f"gross={int(baseline_stats.get('gross_findings', 0))}, "
            f"scored={int(baseline_stats.get('scored_findings', 0))}, "
            f"accepted={int(baseline_stats.get('accepted_debt', 0))}, "
            f"new={int(baseline_stats.get('new_findings', 0))}, "
            f"resolved={int(baseline_stats.get('resolved_findings', 0))}, "
            f"suppressed_duplicates={int(dedupe_stats.get('suppressed_count', 0))}"
        )
        java_cache = summary.score_card.get("java_cache", {}) if isinstance(summary.score_card, dict) else {}
        java_hits = int(java_cache.get("cache_hits", 0) or 0)
        java_misses = int(java_cache.get("cache_misses", 0) or 0)
        if (java_hits + java_misses) > 0:
            typer.echo(f"Java cache: {java_hits} hits / {java_misses} misses")
            reason_counts = java_cache.get("miss_reason_counts", {})
            if isinstance(reason_counts, dict) and reason_counts:
                compact = " ".join(f"{reason}={count}" for reason, count in sorted(reason_counts.items()))
                typer.echo(f"Miss reasons: {compact}")
        if summary.policy["status"] in {"warn", "fail"}:
            typer.echo(f"Policy reasons: {', '.join(summary.policy['reasons'])}")

    if fail_on_policy:
        if policy.status == PolicyStatus.pass_:
            raise typer.Exit(code=0)
        if policy.status == PolicyStatus.warn:
            raise typer.Exit(code=1)
        if policy.status == PolicyStatus.fail:
            raise typer.Exit(code=2)
        raise typer.Exit(code=3)


@app.command("build-site")
def build_site(path: Path = typer.Argument(Path.cwd())) -> None:
    try:
        services = build_scan_services(path)
        builder = StaticSiteBuilder(reports_root=services.config.reports_dir, site_root=services.config.site_dir)
        output = builder.build()
    except ConfigLoadError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except Exception as exc:
        typer.echo(f"site build failed: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    typer.echo(f"Built site for {output['project_count']} projects at {output['output_dir']}")


@app.command("prune-reports")
def prune_reports(
    path: Path = typer.Argument(Path.cwd()),
    keep: int | None = typer.Option(None, "--keep", min=1),
    days: int | None = typer.Option(None, "--days", min=1),
    project: list[str] | None = typer.Option(None, "--project"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    if (keep is None and days is None) or (keep is not None and days is not None):
        typer.echo("Specify exactly one retention mode: --keep N or --days N.", err=True)
        raise typer.Exit(code=3)

    try:
        config = load_resolved_config(path.expanduser().resolve())
    except ConfigLoadError as exc:
        raise typer.BadParameter(str(exc)) from exc

    store = ScanArtifactStore(config.reports_dir)
    projects = store.list_projects()
    requested_projects = project or []
    if requested_projects:
        missing_projects = sorted({name for name in requested_projects if name not in projects})
        if missing_projects:
            typer.echo(f"Project(s) not found in reports: {', '.join(missing_projects)}", err=True)
            raise typer.Exit(code=3)
        unique_requested: list[str] = []
        seen: set[str] = set()
        for name in requested_projects:
            if name in seen:
                continue
            seen.add(name)
            unique_requested.append(name)
        projects = unique_requested
    removed_total = 0
    scanned_total = 0
    selected_by_project: dict[str, list[str]] = {}
    latest_preserved_all = True
    projects_affected = 0

    for project_name in projects:
        count = len(store.list_scan_dirs(project_name))
        scanned_total += count
        if keep is not None:
            selected = store.select_scans_to_prune_keep(project_name, keep=keep)
            selected_by_project[project_name] = [info.scan_id for info in selected]
            if dry_run:
                removed = len(selected)
            else:
                removed = store.prune_scans(project_name, keep=keep)
            removed_total += removed
            latest_preserved = store.latest_preserved(project_name)
            latest_preserved_all = latest_preserved_all and latest_preserved
            typer.echo(
                f"{project_name}: scans={count}, "
                f"{'would_remove' if dry_run else 'removed'}={removed} (keep={keep}), "
                f"latest preserved: {'yes' if latest_preserved else 'no'}"
            )
            continue

        assert days is not None
        selected = store.select_scans_to_prune_days(project_name, days=days)
        selected_by_project[project_name] = [info.scan_id for info in selected]
        removed = store.prune_scans_older_than(project_name, days=days, dry_run=dry_run)
        removed_total += removed
        latest_preserved = store.latest_preserved(project_name)
        latest_preserved_all = latest_preserved_all and latest_preserved
        typer.echo(
            f"{project_name}: scans={count}, "
            f"{'would_remove' if dry_run else 'removed'}={removed} (days={days}), "
            f"latest preserved: {'yes' if latest_preserved else 'no'}"
        )

    mode_desc = f"keep={keep}" if keep is not None else f"days={days}"
    if dry_run:
        projects_affected = sum(1 for ids in selected_by_project.values() if ids)
        selected_total = sum(len(ids) for ids in selected_by_project.values())
        typer.echo(f"Dry run: yes")
        typer.echo(f"latest preserved: {'yes' if latest_preserved_all else 'no'}")
        for project_name in sorted(selected_by_project.keys()):
            ids = sorted(selected_by_project[project_name])
            if not ids:
                continue
            typer.echo(f"Project: {project_name}")
            typer.echo(f"Would remove: {len(ids)} scans")
            for scan_id in ids:
                typer.echo(f"- {scan_id}")
        if selected_total == 0:
            typer.echo("Would remove: (none)")
        typer.echo(f"Total scans selected: {selected_total}")
        typer.echo(f"Projects affected: {projects_affected}")
    typer.echo(
        f"Prune summary: projects={len(projects)}, scans={scanned_total}, "
        f"{'would_remove' if dry_run else 'removed'}={removed_total}, mode={mode_desc}."
    )


@app.command()
def list_scanners(json_output: bool = typer.Option(False, "--json")) -> None:
    registry = ScannerRegistry([])
    register_builtin_scanners(registry)
    parser_registry = ParserRegistry()
    register_builtin_parsers(parser_registry)
    payload: list[dict[str, str | bool]] = []
    for scanner in registry.scanners:
        available = scanner.is_available()
        parser_registered = parser_registry.get(scanner.scanner_name) is not None
        expected_parser = parser_registry.expected_parser(scanner.scanner_name)
        if not available:
            status = "unavailable"
        elif parser_registered:
            status = "ready"
        else:
            status = "incomplete"
        payload.append(
            {
                "scanner_name": scanner.scanner_name,
                "available": available,
                "parser_registered": parser_registered,
                "expected_parser": expected_parser,
                "status": status,
            }
        )
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    typer.echo("Available scanners:")
    for row in payload:
        typer.echo(
            f"- {row['scanner_name']} | available={str(row['available']).lower()} "
            f"| parser_registered={str(row['parser_registered']).lower()} "
            f"| expected_parser={row['expected_parser']} | status={row['status']}"
        )


@app.command()
def show_config(path: Path = typer.Argument(Path.cwd()), human: bool = False) -> None:
    try:
        config = load_resolved_config(path.expanduser().resolve())
    except ConfigLoadError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if human:
        typer.echo(f"reports_dir: {config.reports_dir}")
        typer.echo(f"site_dir: {config.site_dir}")
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
    module: str | None = typer.Option(None, "--module"),
    tool: str | None = typer.Option(None, "--tool"),
    json_output: bool = typer.Option(True, "--json/--human"),
) -> None:
    project_root = project_path.expanduser().resolve()
    service = JavaBuildCacheService(project_root)
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
    module: str | None = typer.Option(None, "--module"),
    tool: str | None = typer.Option(None, "--tool"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    project_root = project_path.expanduser().resolve()
    service = JavaBuildCacheService(project_root)
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
    days: int = typer.Option(30, "--days", min=1),
    max_history: int = typer.Option(10, "--max-history", min=1),
    project: list[str] | None = typer.Option(None, "--project"),
    module: str | None = typer.Option(None, "--module"),
    tool: str | None = typer.Option(None, "--tool"),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    project_root = project_path.expanduser().resolve()
    service = JavaBuildCacheService(project_root)
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
    output: Path = typer.Option(Path("baseline.json"), "--output"),
    owner: str | None = typer.Option(None, "--owner"),
    note: str | None = typer.Option(None, "--note"),
    expires_days: int | None = typer.Option(None, "--expires-days", min=1),
    dry_run: bool = typer.Option(False, "--dry-run"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    try:
        services = build_scan_services(project_path)
    except ConfigLoadError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=3) from exc
    except Exception as exc:
        typer.echo(f"baseline init failed: {exc}", err=True)
        raise typer.Exit(code=3) from exc

    project = services.project
    results = services.orchestrator.run(project)
    extractor = MetricsExtractor()
    deduped_results = extractor.dedupe_scan_results(results)
    dedupe_meta = extractor.last_duplicate_metadata

    findings = [
        finding
        for result in deduped_results
        if result.success
        for finding in result.findings
    ]
    created_at = datetime.now(UTC)
    expires_at = (created_at + timedelta(days=expires_days)) if expires_days is not None else None
    baseline_service = BaselineService()
    entries = [
        baseline_service.build_entry_payload(
            fingerprint=finding_fingerprint(finding, include_tool=True),
            accepted=True,
            owner=owner,
            note=note,
            created_at=created_at,
            expires_at=expires_at,
        )
        for finding in findings
    ]
    payload = {"entries": entries}

    output_path = output if output.is_absolute() else project.path / output
    if output_path.exists() and not force and not dry_run:
        typer.echo(f"Refusing to overwrite existing baseline file: {output_path}", err=True)
        raise typer.Exit(code=3)

    if dry_run:
        sample = entries[:5]
        typer.echo("Dry run: yes")
        typer.echo(f"Output path: {output_path}")
        typer.echo(f"Entries to generate: {len(entries)}")
        typer.echo(f"Suppressed duplicates excluded: {int(dedupe_meta.get('suppressed_count', 0))}")
        if sample:
            typer.echo("Sample entries:")
            typer.echo(json.dumps(sample, indent=2, sort_keys=True))
        else:
            typer.echo("Sample entries: []")
        return

    _atomic_write_json(output_path, payload)
    typer.echo(
        f"Wrote baseline with {len(entries)} entries to {output_path} "
        f"(suppressed duplicates excluded: {int(dedupe_meta.get('suppressed_count', 0))})"
    )
