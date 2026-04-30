# Changelog

## Added - Security Classifier Contract 1.0.0

Introduced stable security finding classification as a post-parse, pre-scoring analysis stage.

New stable contract:

- `classifier.name`
- `classifier.version`
- `classifier.ruleset`
- `security_class`
- `security_context`
- `security_impact`
- `score_weight`
- `classification_reason`
- `classification_rule_id`

Stable reason-code registry introduced:

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

Scoring now honors `score_weight`.  
False positives remain visible but no longer reduce security score.

Contract stability:

- Reason codes are treated as stable identifiers.
- Changing or removing a reason code requires a version bump.

Classifier contract semantic versioning policy:

- Patch (`1.0.0 -> 1.0.1`):
  - wording clarification
  - documentation updates
  - internal implementation changes
  - no contract field changes
- Minor (`1.0.0 -> 1.1.0`):
  - add reason codes
  - add optional metadata
  - add security class values
  - must remain backward compatible
- Major (`1.x -> 2.0.0`):
  - remove reason codes
  - rename reason codes
  - change reason semantics
  - change score meaning
  - remove fields
