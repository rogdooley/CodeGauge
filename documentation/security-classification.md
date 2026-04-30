# Security Classification

## Purpose

Scanner output indicates potential issues, but not all findings have equal exploitability. CodeGauge adds a deterministic post-parse classification layer so security scoring reflects execution context and likely impact while keeping all findings visible.

Pipeline order:

`parse -> normalize -> classify -> dedupe -> baseline -> score -> report`

## Classification Classes

| class | meaning | weight |
| --- | --- | --- |
| `runtime_security` | Production-reachable runtime paths/contexts | `1.0` |
| `tooling_security` | Developer/admin tooling paths | `0.25` |
| `test_security` | Test and smoke-test context | `0.1` |
| `false_positive` | Known heuristic noise | `0.0` |
| `unknown` | Fallback when no deterministic rule matches | `1.0` |

## Rule Precedence

Deterministic rule order is:

1. Exploitability signals (escalation)
2. Rule-specific security exceptions
3. Path context defaults
4. Unknown fallback

This enforces `exploitability > path > severity`.

## Deterministic Rules

- Runtime paths under `src/`, `app/`, `services/`, `api/`, `middleware/` keep full weighting.
- Tooling paths under `tools/`, `scripts/`, `dev/`, `maintenance/` are reduced by default.
- Test paths under `tests/` or `smoke_test.py` are reduced to test weighting.
- Bandit `B105` suspicious literal tokens `""`, `(`, `)`, `NOT`, `AND`, `OR` are classified as false positives with zero weight.
- Bandit `B404`/`B603` under tooling paths are reduced unless exploitability escalation signals are present.
- Bandit `B310` in tests/smoke paths is test-only security with reduced weight.

Escalation signals for tooling-path command execution findings include:

- `shell=True`
- `os.system(...)`
- `subprocess.Popen(...)`
- interpolated command construction (for example `run(f"...{var}...")`)

Escalated findings are classified as `runtime_security` with weight `1.0`.

## Stable Reason Codes

Classification outputs use canonical, stable identifiers:

- `non_security_category`
- `path_runtime`
- `path_tooling`
- `path_test`
- `bandit_b105_token_literal`
- `bandit_b404_tool_subprocess`
- `bandit_b603_tool_subprocess`
- `bandit_b603_shell_true`
- `bandit_b310_test_urlopen`
- `heuristic_interpolated_command`
- `default_unknown`

Per finding fields:

- `classification_reason` (stable canonical identifier)
- `classification_rule_id` (same canonical identifier for machine filtering)
- `classification_detail` (optional human detail)

## Provenance and Versioning

Each summary includes classifier provenance metadata:

```json
{
  "classifier": {
    "name": "security_classifier",
    "version": "1.0.0",
    "ruleset": "default"
  }
}
```

This makes score movement auditable when rules change across versions.

Machine-readable contract snapshot:

- `schemas/security-classification.schema.json`

Regeneration command:

- `uv run python -m codegauge.tools.generate_contracts`
