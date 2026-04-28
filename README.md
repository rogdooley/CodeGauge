# codegauge

codegauge is a modular, local-first engineering-quality platform built with `uv`.
It provides a reusable architecture for scanning multiple languages, starting with Python,
and generates static leadership-friendly reports without depending on CI.

## CLI

- `codegauge show-config <path>` prints fully resolved config as JSON.
- `codegauge scan <path>` runs enabled scanners for the discovered project languages.
- `codegauge scan <path> --json` prints a machine-readable scan summary with per-scanner status.
- `codegauge scan <path> --json --verbose` includes command and raw execution metadata for each scanner.
- `codegauge scan <path> --fail-on-policy` maps policy status to exit code for CI:
  - `0` = `pass`
  - `1` = `warn`
  - `2` = `fail`
  - `3` = execution/internal failure
- `codegauge build-site [path]` generates static leadership-friendly HTML from persisted report artifacts.
- `codegauge prune-reports [path] --keep N [--dry-run]` prunes historical scans while keeping the newest N per project.
- `codegauge prune-reports [path] --days N [--dry-run]` prunes scans older than N days per project.

## Artifacts

Each scan persists artifacts under:

- `reports/<project>/scans/<timestamp>/`
- `reports/<project>/latest/`

Artifacts include `summary.json`, `findings.json`, `score.json`, `policy.json`, and `raw/<scanner>.json`.

## Scanner Selection

- If `enabled_scanners` is empty, all supported scanners are eligible.
- `disabled_scanners` removes scanners from the eligible set.
- Any overlap between `enabled_scanners` and `disabled_scanners` fails closed during config validation.
