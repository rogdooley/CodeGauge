from __future__ import annotations

from pathlib import Path

import typer

from ..bootstrap.factory import load_resolved_config_with_overrides
from ..config import ConfigLoadError
from ..storage import ScanArtifactStore


def prune_reports_handler(
    *,
    path: Path,
    keep: int | None,
    days: int | None,
    project: list[str] | None,
    report_root: Path | None,
    state_root: Path | None,
    dry_run: bool,
) -> None:
    if (keep is None and days is None) or (keep is not None and days is not None):
        typer.echo("Specify exactly one retention mode: --keep N or --days N.", err=True)
        raise typer.Exit(code=3)

    try:
        config = load_resolved_config_with_overrides(
            path.expanduser().resolve(),
            report_root=report_root,
            state_root=state_root,
            open_report=None,
        )
    except ConfigLoadError as exc:
        raise typer.BadParameter(str(exc)) from exc

    store = ScanArtifactStore(config.report_root)
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

    for project_name in projects:
        count = len(store.list_scan_dirs(project_name))
        scanned_total += count
        if keep is not None:
            selected = store.select_scans_to_prune_keep(project_name, keep=keep)
            selected_by_project[project_name] = [info.scan_id for info in selected]
            removed = len(selected) if dry_run else store.prune_scans(project_name, keep=keep)
            removed_total += removed
            latest_preserved = store.latest_preserved(project_name)
            latest_preserved_all = latest_preserved_all and latest_preserved
            typer.echo(
                f"{project_name}: scans={count}, "
                f"{'would_remove' if dry_run else 'removed'}={removed} (keep={keep}), "
                f"latest preserved: {'yes' if latest_preserved else 'no'}"
            )
            continue

        if days is None:
            raise typer.BadParameter("--days is required when --keep is not set")
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
        typer.echo("Dry run: yes")
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
