from __future__ import annotations

import hashlib
import json
from pathlib import Path
from time import perf_counter
from typing import Callable

import typer

from ..baseline import BaselineService
from ..config import ConfigLoadError
from ..constants import ExitCode, InternalErrorCode
from ..policy import CodeGaugePolicyEngine
from ..reporting import StaticSiteBuilder
from ..scoring import CodeGaugeScoringEngine
from ..services.metrics import MetricsExtractor
from ..services.recommendation_engine import RecommendationEngine, strip_internal_scores
from ..services.report_normalizer import FINGERPRINT_VERSION, MESSAGE_NORMALIZER_VERSION, finding_sort_key, normalize_finding_record
from ..storage import ScanArtifactStore


def scan_handler(
    *,
    path: Path,
    json_output: bool,
    verbose: bool,
    report_root: Path | None,
    state_root: Path | None,
    open_report: bool | None,
    fail_on_policy: bool,
    capture_full_raw: bool,
    collect_scalar_metrics: Callable,
    collect_java_cache_summary: Callable,
    to_scan_summary: Callable,
    compact_scanner_raw_output: Callable,
    summary_exit_code: Callable,
    render_scan_human_summary: Callable,
    load_config_fn: Callable,
    build_services_fn: Callable,
    open_browser_fn: Callable,
) -> None:
    resolved_path = path.expanduser().resolve()
    try:
        resolved_config = load_config_fn(
            resolved_path,
            report_root=report_root,
            state_root=state_root,
            open_report=open_report,
        )
        resolved_config.state_root.mkdir(parents=True, exist_ok=True)
        (resolved_config.state_root / "cache").mkdir(parents=True, exist_ok=True)
        (resolved_config.state_root / "logs").mkdir(parents=True, exist_ok=True)
        (resolved_config.state_root / "tmp").mkdir(parents=True, exist_ok=True)
        services = build_services_fn(resolved_path, resolved_config)
    except ConfigLoadError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=int(ExitCode.config_error)) from exc
    except typer.Exit:
        raise
    except KeyboardInterrupt as exc:
        typer.echo(str(InternalErrorCode.interrupted), err=True)
        raise typer.Exit(code=int(ExitCode.interrupted)) from exc
    except Exception as exc:
        typer.echo(f"scan execution failed: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.internal_error)) from exc

    legacy_root = resolved_path / ".codegauge"
    if legacy_root.exists():
        typer.echo(
            f"Notice: legacy local storage at {legacy_root} is deprecated; new artifacts are written to {services.config.report_root}",
            err=True,
        )

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
            raise typer.Exit(code=int(ExitCode.config_error))
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
        score_payload["scalar_metrics"] = collect_scalar_metrics(results)
        score_payload["measured_categories"] = sorted({metric.category.value for metric in metrics})
        score_payload["dedupe"] = metrics_extractor.last_duplicate_metadata
        score_payload["baseline"] = baseline_application.stats.model_dump(mode="json")
        score_payload["java_cache"] = collect_java_cache_summary(results)

        pre_policy_summary = to_scan_summary(
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
                if bucket[key] > parser_summary_global.get(key, 0):
                    bucket[key] = parser_summary_global.get(key, 0)
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
        summary_payload["scanner_stats"] = [
            {
                "scanner_name": result.scanner_name,
                "scanner_input_file_count": int(result.metadata.get("scanner_input_file_count", 0) or 0),
                "success": result.success,
                "error_code": result.error_code,
            }
            for result in results
        ]
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
        raw_outputs = {result.scanner_name: compact_scanner_raw_output(result) for result in results}
        store = ScanArtifactStore(services.config.report_root)
        history = store.load_project_scan_history(project.name)
        previous_summary = history[-1].get("summary", {}) if history else None
        recommendation_engine = RecommendationEngine()
        action_plan_payload = recommendation_engine.generate(
            findings=findings_payload,
            metrics=score_payload,
            project_summary=summary_payload,
            previous_run_summary=previous_summary,
        )
        action_plan_payload = strip_internal_scores(action_plan_payload)
        store.persist_scan_artifacts(
            project_name=project.name,
            summary=summary_payload,
            findings=findings_payload,
            score=summary.score_card or {},
            policy=summary.policy or {},
            action_plan=action_plan_payload,
            scanner_raw_outputs=raw_outputs,
        )
        builder = StaticSiteBuilder(report_root=services.config.report_root)
        builder.build()
    except typer.Exit:
        raise
    except Exception as exc:
        typer.echo(f"scan execution failed: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.internal_error)) from exc

    if json_output:
        payload = dict(summary_payload)
        for entry in payload["results"]:
            entry.setdefault("error_code", None)
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        render_scan_human_summary(project_name=project.name, results=results, summary=summary, report_root=services.config.report_root)

    should_open = bool(open_report if open_report is not None else services.config.open_report)
    if should_open:
        opened, message = open_browser_fn(services.config.report_root / "index.html")
        if opened:
            typer.echo(message)
        else:
            typer.echo(f"Info: {message}", err=True)

    if fail_on_policy:
        raise typer.Exit(code=summary_exit_code(results, policy.status, policy_gate=True))
    raise typer.Exit(code=summary_exit_code(results, policy.status, policy_gate=False))
