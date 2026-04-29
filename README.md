# codegauge

codegauge is a modular, local-first engineering-quality platform built with `uv`.
It provides a reusable architecture for scanning multiple languages, starting with Python,
and generates static leadership-friendly reports without depending on CI.

## CLI

- `codegauge show-config <path>` prints fully resolved config as JSON.
- `codegauge scan <path>` runs enabled scanners for the discovered project languages.
- `codegauge scan <path> --open` opens the generated static report portal index in the default browser (headless-safe).
- `codegauge scan <path> --json` prints a machine-readable scan summary with per-scanner status.
- `codegauge scan <path> --json --verbose` includes command and raw execution metadata for each scanner.
- `codegauge scan <path> --fail-on-policy` maps policy status to exit code for CI:
  - `0` = `pass`
  - `1` = `warn`
  - `2` = `fail`
  - execution failures use fixed taxonomy:
    - `3` = config error
    - `4` = scanner failure
    - `5` = parser failure
    - `6` = internal error
    - `7` = interrupted
- `codegauge build-site [path]` generates static leadership-friendly HTML from persisted report artifacts.
- `codegauge open [path]` opens the report portal root index for the resolved report root.
- `codegauge prune-reports [path] --keep N [--dry-run]` prunes historical scans while keeping the newest N per project.
- `codegauge prune-reports [path] --days N [--dry-run]` prunes scans older than N days per project.

## Artifacts

Each scan persists artifacts under:

- `<report_root>/projects/<project>/runs/YYYY-MM-DD_HHMMSS/`
- `<report_root>/projects/<project>/latest/`

Artifacts include `summary.json`, `findings.json`, `score.json`, `policy.json`, `run_manifest.json`, `report.html`, and `raw/<scanner>.json`.

Portal index is generated at `<report_root>/index.html`.

## Default Roots

- **Report root (visible)**
  - Linux/macOS: `~/Documents/CodeGauge`
  - Windows: `%USERPROFILE%\Documents\CodeGauge`
- **State root (hidden/internal)**
  - Linux: `$XDG_DATA_HOME/codegauge` or `~/.local/share/codegauge`
  - macOS: `~/Library/Application Support/CodeGauge`
  - Windows: `%LOCALAPPDATA%\CodeGauge`

Config keys:

- `report_root`
- `state_root`
- `open_report`

CLI overrides:

- `--report-root`
- `--state-root`
- `--open` / `--no-open`

## Scanner Selection

- If `enabled_scanners` is empty, all supported scanners are eligible.
- `disabled_scanners` removes scanners from the eligible set.
- Any overlap between `enabled_scanners` and `disabled_scanners` fails closed during config validation.
