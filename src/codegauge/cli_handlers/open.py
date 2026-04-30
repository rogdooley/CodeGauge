from __future__ import annotations

from pathlib import Path

import typer

from ..config import ConfigLoadError
from ..constants import ExitCode


def open_portal_handler(*, path: Path, report_root: Path | None, state_root: Path | None, load_config_fn, open_browser_fn) -> None:
    resolved_path = path.expanduser().resolve()
    try:
        config = load_config_fn(
            resolved_path,
            report_root=report_root,
            state_root=state_root,
        )
    except ConfigLoadError as exc:
        raise typer.BadParameter(str(exc)) from exc
    portal = config.report_root / "index.html"
    if not portal.exists():
        typer.echo(
            f"No report portal found at {portal}. Run 'codegauge scan {resolved_path}' or 'codegauge build-site {resolved_path}' first."
        )
        raise typer.Exit(code=int(ExitCode.success))
    opened, message = open_browser_fn(portal)
    if opened:
        typer.echo(message)
        return
    typer.echo(f"Info: {message}")
