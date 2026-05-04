# Security

## Secret Scanning Model

CodeGauge secrets scanning uses:

- tracked files (always)
- ignored sensitive files (selective high-risk patterns)
- explicit exclusion of known junk/generated/cache paths

## Ignored Sensitive Files

Ignored files are not blanket-skipped for secrets analysis. High-risk ignored files are included via effective sensitive pattern rules.

## History Scanning

History scanning is a separate workflow and should run on a schedule. Findings from commit history are classified as `historical_secret_exposure`.

History freshness uses three states:

- `never_scanned`
- `fresh`
- `stale`

## Verified vs Probable

- Verified/real secret and private key findings are treated as hard security failures.
- Probable findings remain visible and policy-warned for triage.

## Intentional Security Material Exclusions

The secrets heuristic intentionally suppresses benign security constructs when context demonstrates expected use:

- CSRF hidden inputs
- TOTP enrollment bootstrap material
- login challenge/state tokens
- opaque flash identifiers
- signed pagination cursors (non-capability)

Suppression requires contextual evidence. Variable names alone are never sufficient.

## Disclosure

Report security issues privately through the project maintainer contact channel before public disclosure.
