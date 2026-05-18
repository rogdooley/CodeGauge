# Configuration

All configuration is in `.codegauge.toml`.

## Core

- `report_root`
- `state_root`
- `open_report`
- `default_timeout_seconds`
- `exclude`
- `enabled_scanners`
- `disabled_scanners`

## Scanner Settings

Use `[scanners.<name>]` for per-scanner settings:

- `enabled`
- `timeout_seconds`
- `extra_args`

## Thresholds

`[thresholds]` supports score and severity guardrails.

## Secrets

`[secrets]` supports:

- `enabled`
- `history_scan_enabled`
- `history_commit_limit`
- `history_size_limit_mb`
- `exclude_fixtures`
- `fail_on_secret`
- `ignored_sensitive_patterns_add`
- `ignored_sensitive_patterns_remove`

Pattern behavior is additive/subtractive only: built-in defaults are preserved, then adds are applied, then removes are subtracted.

## Payload

`[payload]` controls raw payload capture, redaction, and size limits.

## UI

`[ui]` supports onboarding and terminal guidance behavior:

- `disable_bootstrap_hints` (default `false`)

When `false`, `codegauge scan` may show an interactive tip for unmanaged projects (missing `.codegauge.toml` and no recognizable linter/static-analysis config in project root). Hints are suppressed for JSON output, CI environments, and non-interactive terminals.
