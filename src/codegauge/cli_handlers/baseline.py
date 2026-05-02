from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable

import typer

from ..baseline import BaselineService
from ..config import ConfigLoadError
from ..services.metrics import MetricsExtractor, finding_fingerprint


def baseline_init_handler(
    *,
    project_path: Path,
    report_root: Path | None,
    state_root: Path | None,
    output: Path,
    owner: str | None,
    note: str | None,
    expires_days: int | None,
    dry_run: bool,
    force: bool,
    atomic_write_json: Callable[[Path, object], None],
    to_int: Callable[[object, int], int],
    load_config_fn: Callable,
    build_services_fn: Callable,
) -> None:
    try:
        resolved_project = project_path.expanduser().resolve()
        resolved_config = load_config_fn(
            resolved_project,
            report_root=report_root,
            state_root=state_root,
        )
        services = build_services_fn(resolved_project, resolved_config)
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

    findings = [finding for result in deduped_results if result.success for finding in result.findings]
    prohibited_real_secrets = [
        finding
        for finding in findings
        if bool(getattr(finding, "raw_payload", {}).get("secret_real"))
    ]
    if prohibited_real_secrets:
        typer.echo(
            "baseline init rejected: baseline acceptance is prohibited for real secret findings.",
            err=True,
        )
        raise typer.Exit(code=3)
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
        typer.echo(f"Suppressed duplicates excluded: {to_int(dedupe_meta.get('suppressed_count', 0))}")
        if sample:
            import json

            typer.echo("Sample entries:")
            typer.echo(json.dumps(sample, indent=2, sort_keys=True))
        else:
            typer.echo("Sample entries: []")
        return

    atomic_write_json(output_path, payload)
    typer.echo(
        f"Wrote baseline with {len(entries)} entries to {output_path} "
        f"(suppressed duplicates excluded: {to_int(dedupe_meta.get('suppressed_count', 0))})"
    )
