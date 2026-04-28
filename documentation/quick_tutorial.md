# CodeGauge Quick Tutorial

This guide shows the fastest way to run CodeGauge across common project types.

## Prerequisites

- Run commands from the CodeGauge repo root.
- Use project roots as scan targets (not nested `src/` or `app/` folders).

## Verify CLI

```bash
uv run codegauge --help
uv run codegauge list-scanners --json
```

## 1) Python Project

Example target:

```bash
~/Documents/gitprojects/my-python-service
```

Run:

```bash
uv run codegauge scan ~/Documents/gitprojects/my-python-service
```

JSON output:

```bash
uv run codegauge scan ~/Documents/gitprojects/my-python-service --json
```

## 2) Django Project

Example target:

```bash
~/Documents/gitprojects/my-django-app
```

Run:

```bash
uv run codegauge scan ~/Documents/gitprojects/my-django-app
```

Tip: use project root containing `manage.py` and settings/modules, not a template or app subfolder.

## 3) JavaScript / TypeScript Project

Example target:

```bash
~/Documents/gitprojects/my-web-ui
```

Run:

```bash
uv run codegauge scan ~/Documents/gitprojects/my-web-ui
```

Tip: target should contain `package.json` (and usually `tsconfig.json` for TS).

## 4) Java Project (Spring, Micronaut, Quarkus, Jakarta EE)

Example target:

```bash
~/Documents/gitprojects/my-java-service
```

Run:

```bash
uv run codegauge scan ~/Documents/gitprojects/my-java-service
```

For Java cache diagnostics:

```bash
uv run codegauge cache status ~/Documents/gitprojects/my-java-service --json
```

## Inspect Effective Config

```bash
uv run codegauge show-config ~/Documents/gitprojects/my-project
```

## Policy-driven CI Exit Codes

```bash
uv run codegauge scan ~/Documents/gitprojects/my-project --fail-on-policy
echo $?
```

Exit code semantics:

- `0` = policy pass
- `1` = policy warn
- `2` = policy fail
- `3` = execution/internal failure

## Common Failure: Wrong Scan Path

If you scan a nested folder that is not a project root, scanners may not resolve.

Current behavior is fail-closed:

- scan exits with code `3`
- message indicates no scanners resolved

Fix: run scan against the repository root (where project descriptors live).

## Generate and Browse Site Reports

After one or more scans:

```bash
uv run codegauge build-site ~/Documents/gitprojects/my-project
```

Outputs HTML under the configured `site_dir`.
