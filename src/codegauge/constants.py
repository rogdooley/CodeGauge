from __future__ import annotations

from enum import IntEnum, StrEnum


class ExitCode(IntEnum):
    success = 0
    policy_warning = 1
    policy_fail = 2
    config_error = 3
    scanner_failure = 4
    parser_failure = 5
    internal_error = 6
    interrupted = 7


class ParserRuleId(StrEnum):
    missing_rule_id = "CODEGAUGE.PARSER.MISSING_RULE_ID"
    invalid_path = "CODEGAUGE.PARSER.INVALID_PATH"
    bad_severity = "CODEGAUGE.PARSER.BAD_SEVERITY"
    schema_error = "CODEGAUGE.PARSER.SCHEMA_ERROR"
    oversize_payload = "CODEGAUGE.PARSER.OVERSIZE_PAYLOAD"
    unhandled = "CODEGAUGE.PARSER.UNHANDLED"


class ScannerErrorCode(StrEnum):
    contract_violation = "scanner_contract_violation"
    binary_missing = "scanner_binary_missing"
    config_error = "scanner_config_error"
    nonzero_exit = "scanner_nonzero_exit"
    timeout = "scanner_timeout"


class ParserErrorCode(StrEnum):
    parser_missing = "scanner_parser_missing"
    parse_error = "scanner_parse_error"
    output_invalid = "scanner_output_invalid"
    finding_path_invalid = "finding_path_invalid"


class ConfigErrorCode(StrEnum):
    invalid_config = "CODEGAUGE.CONFIG.INVALID_CONFIG"
    load_failed = "CODEGAUGE.CONFIG.LOAD_FAILED"


class PolicyErrorCode(StrEnum):
    scanner_failure = "CODEGAUGE.POLICY.SCANNER_FAILURE"
    parser_failure = "CODEGAUGE.POLICY.PARSER_FAILURE"


class InternalErrorCode(StrEnum):
    unhandled = "CODEGAUGE.INTERNAL.UNHANDLED"
    interrupted = "CODEGAUGE.INTERNAL.INTERRUPTED"


class DisabledReason(StrEnum):
    framework_incompatible = "framework_incompatible"
