# CodeGauge Operational Checklist (Phase 1 Ship)

## First-run validation

Expected:
- Detected framework: `fastapi` for Python service projects without Django evidence.
- Django scanners disabled with reason `framework_incompatible` when framework is not Django.
- `.venv` content excluded from inventory/scanning scope.
- Ownership tagging present on every normalized finding.
- Fingerprints stable across reruns when findings are semantically unchanged.
- Deterministic finding ordering identical across equivalent reruns.
- `parser_summary` emitted with deterministic keys and zero counts present.
- `report_sha256` present in summary artifact.
- `schema_version` present in summary artifact.

## Artifact checklist

Final report artifacts include:
- `findings`
- `inventory`
- `policy_resolution`
- `parser_summary`
- `scanner_stats` (from per-scanner results metadata)
- `schema_version`
- `fingerprint_version`
- `message_normalizer_version`
- `report_sha256`

## Negative checks

Verify:
- Malformed finding input emits `CODEGAUGE.PARSER.*` finding instead of aborting the scan.
- Oversized raw payload is truncated and redacted by default.
- Full raw payload capture requires both config opt-in and CLI opt-in.
