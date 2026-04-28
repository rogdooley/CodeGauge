# Policy Reason Taxonomy v1

This document defines stable machine-readable reason codes emitted in `policy.reasons`.

## scanner_failure
- Severity: fail
- Meaning: One or more scanners failed to execute successfully.
- Trigger: `scanner_failures > 0`
- Remediation: Install/fix scanner binaries and resolve scanner runtime errors before accepting results.

## parser_missing
- Severity: fail
- Meaning: A scanner completed but no parser was registered for its output.
- Trigger: `parser_missing > 0`
- Remediation: Register the expected parser in the parser registry and verify integration tests.

## invalid_findings
- Severity: fail
- Meaning: Findings were rejected during normalization.
- Trigger: `invalid_findings > 0`
- Remediation: Fix parser normalization logic and ensure findings conform to canonical schema.

## invalid_paths
- Severity: fail
- Meaning: Finding paths were rejected as unsafe or invalid.
- Trigger: `invalid_paths > 0`
- Remediation: Ensure parser path handling resolves inside project root and blocks traversal/symlink escape.

## baseline_entry_expired
- Severity: warn
- Meaning: One or more baseline entries have passed expiration and are no longer accepted debt.
- Trigger: `baseline.expired_entries > 0`
- Remediation: Refresh baseline ownership/expiry and remediate or re-accept findings intentionally.

## baseline_entry_missing_owner
- Severity: warn
- Meaning: Baseline entries exist without clear ownership.
- Trigger: `baseline.missing_owner_entries > 0`
- Remediation: Set `owner` for every accepted baseline entry.

## baseline_entry_expiring
- Severity: warn
- Meaning: Baseline entries are near expiration and will soon be re-scored as new debt.
- Trigger: `baseline.expiring_soon_entries > 0`
- Remediation: Review and renew or retire expiring debt entries before expiration.

## critical_security_finding
- Severity: fail
- Meaning: At least one critical security issue is present.
- Trigger: Any security metric with `severity=critical` and `count > 0`
- Remediation: Patch or mitigate critical vulnerabilities before release.

## high_security_findings
- Severity: warn
- Meaning: High-severity security findings exceed the warning threshold.
- Trigger: Security metrics with `severity=high` exceed CodeGauge v1 threshold.
- Remediation: Prioritize remediation backlog for high-severity security issues.

## low_score
- Severity: warn/fail
- Meaning: Overall score is below policy thresholds.
- Trigger:
  - Warn when `overall_score < 80`
  - Fail when `overall_score < 60`
- Remediation: Address dominant finding categories and rerun scans to improve score.
