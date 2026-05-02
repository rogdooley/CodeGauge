# Architecture

CodeGauge pipeline is deterministic and local-first:

`discovery -> inventory -> scanner -> parser -> normalization -> dedupe -> baseline -> metrics -> scoring -> policy -> artifacts -> portal`

## Component Contracts

- Discovery: determines language/framework hints and project metadata.
- Inventory: builds tracked and scoped file zones.
- Scanner: executes tool adapters with bounded inputs.
- Parser: converts tool output to canonical findings.
- Normalization: validates, classifies, and stabilizes finding shape.
- Dedupe: removes duplicates deterministically.
- Baseline: suppresses explicitly accepted debt.
- Metrics/Scoring: computes category and overall scores.
- Policy: emits pass/warn/fail with stable reason codes.
- Artifacts/Portal: persists JSON artifacts and static HTML report views.

## Determinism Principles

- Stable ordering and sorting for findings and summaries.
- Stable reason-code and schema contracts.
- Safe defaults for scope and policy behavior.
- No hidden network dependency for core analysis.
