from __future__ import annotations

import ast
import json
import math
import re
from pathlib import Path
from time import perf_counter
from typing import Sequence

from .base import Scanner, ScannerCommandResult

_SENSITIVE_PATH_HINTS = (
    ".env",
    "secrets",
    "credentials",
    "id_rsa",
    "id_dsa",
    ".pem",
    ".p12",
    ".pfx",
    ".key",
    "private",
    "cert",
)
_KEY_LINE_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")
_CERT_LINE_RE = re.compile(r"-----BEGIN CERTIFICATE-----")
_ASSIGNMENT_RE = re.compile(r"(?i)\b([a-z_][a-z0-9_]*)\b\s*[:=]\s*['\"]([^'\"\n#]+)['\"]")
_TOKEN_ASSIGNMENT_RE = re.compile(r"(?i)\b([a-z_][a-z0-9_]*)\b\s*[:=]\s*([A-Za-z0-9_\-./+=]{12,})")

_SUSPICIOUS_VARIABLE_NAMES = {
    "api_key",
    "secret",
    "secret_key",
    "token",
    "private_key",
    "client_secret",
    "access_token",
    "refresh_token",
    "password",
    "challenge_token",
    "login_state_token",
}

_EXCLUDED_VARIABLE_NAMES = {
    "password_hash",
    "verify_password",
    "passwordinput",
    "credential_id",
    "credential",
    "allowcredentials",
    "excludecredentials",
    "credential_blob",
    "secret_length",
    "min_password_length",
}

_ALLOWLIST_VARIABLE_NAMES = {
    "csrf_token",
    "xsrf_token",
    "session_token",
    "reset_token",
    "auth_token",
    "token_bucket",
    "csrfmiddlewaretoken",
    "request_token",
    "id_token",
    "refresh_token",
    "nonce_token",
    "verification_token",
}

_KNOWN_SECRET_PREFIXES = (
    "ghp_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxs-",
    "AKIA",
    "ASIA",
    "sk_live_",
    "sk_test_",
    "AIza",
    "ya29.",
)

_CREDENTIAL_FORMATS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+\b"),
)
_HEX_LONG_RE = re.compile(r"^[A-Fa-f0-9]{32,}$")
_BASE64_LONG_RE = re.compile(r"^[A-Za-z0-9+/=]{32,}$")
_STRIPE_TOKEN_RE = re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+\b")
_PLACEHOLDER_VALUES = {"", '""', "change_me", "replace_me", "example", "placeholder", "<generate>"}
_IGNORED_FILE_PARTS = {"vendor", "dist"}
_URL_CAPABILITY_RULE_ID = "intentional_bearer_issuance_url_transport"
_URL_CAPABILITY_MESSAGE = (
    "Bearer-equivalent capability material is transported in URL query parameters after issuance, increasing exposure via "
    "logs, browser history, referrer propagation, and telemetry capture."
)
_QUERY_PARAM_HINTS = (
    "token",
    "public_token",
    "invite",
    "invite_created",
    "created",
    "invite_code",
    "code",
    "reset_token",
    "api_key",
    "key",
    "session",
    "session_token",
    "challenge_token",
)
_NON_FINDING_PARAM_HINTS = ("csrf_token", "csrftoken", "xsrf", "cursor", "page_token", "offset_token", "flash", "flash_id", "nonce_id")
_CAPABILITY_SUBTYPE_BY_NAME = {
    "public_token": "public_access_token",
    "invite_code": "invite_capability_code",
    "invite_token": "invite_capability_code",
    "reset_token": "reset_token",
    "api_key": "api_key",
    "session_token": "session_token",
    "token": "unknown_capability_token",
}
_NON_FINDING_PARAM_NORMALIZED = {
    "csrf_token",
    "csrftoken",
    "xsrf",
    "cursor",
    "page_token",
    "offset_token",
    "flash",
    "flash_id",
    "nonce_id",
}
_SQL_TEXT_FINDING_TYPE = "unsafe_dynamic_sql_construction"
_SQL_TEXT_RULE_ID = "PY.SQLA.TEXT.UNSAFE_INTERPOLATED"
_SQL_TEXT_REVIEW_FINDING_TYPE = "sqlalchemy_text_review_required"
_SQL_TEXT_REVIEW_RULE_ID = "PY.SQLA.TEXT.UNKNOWN_COMPLEX"
_SQL_IDENTIFIER_WRAPPER_CALLS = {"_quote_ident"}


def _normalize_name(name: str) -> str:
    return "".join(ch for ch in name.lower() if ch.isalnum() or ch == "_")


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = float(len(value))
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _variable_signal(name: str) -> bool:
    normalized = _normalize_name(name)
    if normalized in _ALLOWLIST_VARIABLE_NAMES:
        return False
    if normalized in _EXCLUDED_VARIABLE_NAMES:
        return False
    return normalized in _SUSPICIOUS_VARIABLE_NAMES


def _prefix_signal(value: str) -> bool:
    return value.startswith(_KNOWN_SECRET_PREFIXES)


def _credential_format_signal(value: str) -> bool:
    return any(pattern.search(value) for pattern in _CREDENTIAL_FORMATS)


def _value_signal(value: str) -> bool:
    value = value.strip()
    entropy_high = _entropy(value) >= 3.6 and len(value) >= 20
    return bool(
        entropy_high
        or _JWT_RE.search(value)
        or _KEY_LINE_RE.search(value)
        or re.search(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", value)
        or re.search(r"\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\b", value)
        or _STRIPE_TOKEN_RE.search(value)
        or _HEX_LONG_RE.fullmatch(value)
        or _BASE64_LONG_RE.fullmatch(value)
    )


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("'\"").lower()
    return normalized in _PLACEHOLDER_VALUES


def _is_example_file(rel_lower: str) -> bool:
    name = Path(rel_lower).name
    return name == ".env.example" or ".example" in name or "sample" in name


def _is_ignored_file(rel: str) -> bool:
    rel_lower = rel.lower()
    parts = Path(rel_lower).parts
    if rel_lower.startswith("tests/"):
        return True
    if any(part in _IGNORED_FILE_PARTS for part in parts):
        return True
    return rel_lower.endswith(".min.js")


def _is_doc_or_fixture_context(rel: str) -> bool:
    rel_lower = rel.lower()
    parts = Path(rel_lower).parts
    if rel_lower.startswith("readme") or rel_lower.endswith(".md"):
        return True
    if "documentation" in parts or "designdocuments" in parts or "docs" in parts:
        return True
    if "fixture" in rel_lower or "mock" in rel_lower:
        return True
    if rel_lower.endswith((".yaml", ".yml")) and "example" in rel_lower:
        return True
    return False


def _is_intentional_frontend_token_pattern(line: str) -> bool:
    lower = line.lower()
    if "data-login-state-token" in lower:
        return True
    if "challenge" in lower and "navigator.credentials" in lower:
        return True
    if "challenge" in lower and ("publickey" in lower or "webauthn" in lower):
        return True
    if "challengetoken" in lower and ("bootstrap" in lower or "window." in lower):
        return True
    if "name=\"csrf_token\"" in lower or "name='csrf_token'" in lower:
        return True
    if "getelementbyid('totp-secret')" in lower or 'getelementbyid("totp-secret")' in lower:
        return True
    if "payload.secret" in lower and ".textcontent" in lower:
        return True
    return False


def _is_frontend_context_file(rel_lower: str) -> bool:
    return rel_lower.endswith((".html", ".jinja", ".jinja2", ".j2", ".js"))


def _severity_from_entry(entry_text: str) -> tuple[str, str]:
    text = entry_text.lower()
    high_terms = ("ttl>7d", "ttl > 7", "30 day", "unlimited use", "multi-use", "non-revocable", "admin invite", "privileged", "telemetry", "full url logging")
    low_terms = ("single use", "ttl<=24h", "ttl <= 24h", "revocable", "not logged", "no telemetry")
    if any(term in text for term in high_terms):
        return "high", "high_risk_token_characteristics_or_url_observability"
    if all(term in text for term in low_terms):
        return "low", "single_use_short_ttl_revocable_non_observable"
    return "medium", "default_risk_profile"


def _query_keys_from_text(text: str) -> list[str]:
    lowered = text.lower()
    keys = re.findall(r"[?&]([a-zA-Z_][a-zA-Z0-9_]*)=", lowered)
    if keys:
        return keys
    return re.findall(r"['\"]([a-zA-Z_][a-zA-Z0-9_]*)['\"]\s*:", lowered)


def _query_key_from_text(text: str) -> str | None:
    keys = _query_keys_from_text(text)
    for key in keys:
        if key in _QUERY_PARAM_HINTS:
            return key
    return None


def _is_non_finding_param(name: str) -> bool:
    normalized = _normalize_name(name)
    return normalized in _NON_FINDING_PARAM_NORMALIZED


def _subtype_for_name(name: str) -> str:
    normalized = _normalize_name(name)
    return _CAPABILITY_SUBTYPE_BY_NAME.get(normalized, "unknown_capability_token")


def _dict_key_names(node: ast.Dict) -> set[str]:
    names: set[str] = set()
    for key_node in node.keys:
        if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
            names.add(_normalize_name(str(key_node.value)))
    return names


def _is_intentional_capability_response(dict_node: ast.Dict, leaked_name: str, issued_vars: set[str]) -> bool:
    if leaked_name not in issued_vars:
        return False
    # Intentional one-time/public capability issuance should not be flagged as probable_secret_exposure.
    # Internal auth/session tokens must still be flagged elsewhere.
    capability_keys = {
        "token",
        "public_token",
        "invite_code",
        "invite_created",
        "created",
        "reset_token",
        "share_token",
    }
    return bool(_dict_key_names(dict_node).intersection(capability_keys))


def _signals(variable_name: str, value: str) -> dict[str, object]:
    normalized_name = _normalize_name(variable_name)
    allowlisted = normalized_name in _ALLOWLIST_VARIABLE_NAMES
    entropy_value = _entropy(value)
    return {
        "allowlisted_variable": allowlisted,
        "variable_name": _variable_signal(variable_name),
        "literal_assignment": True,
        "entropy": entropy_value,
        "entropy_signal": entropy_value >= 3.6,
        "length": len(value),
        "length_signal": len(value) >= 16,
        "known_prefixes": _prefix_signal(value),
        "credential_format": _credential_format_signal(value),
        "pem_markers": False,
    }


def _constant_secret_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _extract_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    return None


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _extract_name(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    return ""


def _contains_suspicious_name(node: ast.AST) -> str | None:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and _variable_signal(child.id):
            return child.id
    return None


def _call_symbol(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _call_name(node)
    return ""


def _is_sqlalchemy_text_call(node: ast.Call) -> bool:
    symbol = _call_name(node).lower()
    return symbol == "text" or symbol.endswith(".text")


def _sqlalchemy_import_context(tree: ast.AST) -> tuple[set[str], set[str]]:
    text_symbols: set[str] = set()
    module_symbols: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = (node.module or "").lower()
            if module == "sqlalchemy" or module.startswith("sqlalchemy."):
                for alias in node.names:
                    if alias.name == "text":
                        text_symbols.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.lower()
                if name == "sqlalchemy":
                    module_symbols.add(alias.asname or "sqlalchemy")
    return text_symbols, module_symbols


def _is_resolved_sqlalchemy_text_call(node: ast.Call, sqlalchemy_text_symbols: set[str], sqlalchemy_module_symbols: set[str]) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in sqlalchemy_text_symbols
    if isinstance(func, ast.Attribute) and func.attr == "text":
        base_name = _extract_name(func.value)
        return bool(base_name and base_name in sqlalchemy_module_symbols)
    return False


def _is_constant_string_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_constant_string_expr(node.left) and _is_constant_string_expr(node.right)
    return False


def _collect_string_assignments(tree: ast.AST) -> dict[str, ast.AST]:
    assignments: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = node.value
    return assignments


def _is_constant_string_expr_with_assignments(node: ast.AST, assignments: dict[str, ast.AST], depth: int = 0) -> bool:
    if depth > 4:
        return False
    if _is_constant_string_expr(node):
        return True
    if isinstance(node, ast.Name):
        value = assignments.get(node.id)
        if value is None:
            return False
        return _is_constant_string_expr_with_assignments(value, assignments, depth + 1)
    return False


def _is_name_local_function_param(name: str, func_node: ast.FunctionDef | ast.AsyncFunctionDef | None) -> bool:
    if func_node is None:
        return False
    positional = [arg.arg for arg in func_node.args.args]
    positional_only = [arg.arg for arg in func_node.args.posonlyargs]
    keyword_only = [arg.arg for arg in func_node.args.kwonlyargs]
    vararg = [func_node.args.vararg.arg] if func_node.args.vararg is not None else []
    kwarg = [func_node.args.kwarg.arg] if func_node.args.kwarg is not None else []
    return name in set(positional + positional_only + keyword_only + vararg + kwarg)


def _contains_unsafe_name(node: ast.AST, *, func_node: ast.FunctionDef | ast.AsyncFunctionDef | None) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and _is_name_local_function_param(child.id, func_node):
            return True
    return False


def _classify_sqlalchemy_text_call(
    node: ast.Call,
    *,
    assignments: dict[str, ast.AST],
    func_node: ast.FunctionDef | ast.AsyncFunctionDef | None,
) -> str:
    if not node.args:
        return "CONSTANT_LITERAL"
    expr = node.args[0]
    if isinstance(expr, ast.JoinedStr):
        formatted_nodes = [part.value for part in expr.values if isinstance(part, ast.FormattedValue)]
        if not formatted_nodes:
            return "CONSTANT_LITERAL"
        unresolved_parts: list[ast.AST] = []
        for part in formatted_nodes:
            if isinstance(part, ast.Call):
                symbol = _call_symbol(part).lower()
                if symbol in _SQL_IDENTIFIER_WRAPPER_CALLS:
                    unresolved_parts.append(part)
                    continue
            if _contains_unsafe_name(part, func_node=func_node):
                return "UNSAFE_INTERPOLATED"
            unresolved_parts.append(part)
        if not unresolved_parts:
            return "CONSTANT_LITERAL"
        if all(_is_constant_string_expr_with_assignments(part, assignments) for part in unresolved_parts):
            return "CONSTANT_LITERAL"
        return "UNKNOWN_COMPLEX"
    if isinstance(expr, ast.BinOp):
        if isinstance(expr.op, ast.Add):
            if _is_constant_string_expr_with_assignments(expr, assignments):
                return "CONSTANT_LITERAL"
            if _contains_unsafe_name(expr, func_node=func_node):
                return "UNSAFE_INTERPOLATED"
            return "UNKNOWN_COMPLEX"
        if isinstance(expr.op, ast.Mod):
            return "UNSAFE_INTERPOLATED" if _contains_unsafe_name(expr, func_node=func_node) else "UNKNOWN_COMPLEX"
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
        return "UNSAFE_INTERPOLATED" if _contains_unsafe_name(expr, func_node=func_node) else "UNKNOWN_COMPLEX"
    if isinstance(expr, ast.Name):
        if _is_constant_string_expr_with_assignments(expr, assignments):
            return "CONSTANT_LITERAL"
        return "UNKNOWN_COMPLEX"
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        value = expr.value
        if re.search(r":[a-zA-Z_][a-zA-Z0-9_]*", value):
            return "SAFE_BOUND"
        return "CONSTANT_LITERAL"
    return "UNKNOWN_COMPLEX"


def _is_capability_issuer_call(node: ast.AST) -> bool:
    symbol = _call_symbol(node).lower()
    if symbol in {"secrets.token_urlsafe", "secrets.token_hex", "uuid.uuid4"}:
        return True
    return bool(
        re.search(r"(create|generate|issue)_[a-z0-9_]*(token|invite|share|public_link|api_key|session)", symbol)
        or re.search(r"(token|invite|share|public_link|api_key|session).*?(create|generate|issue)", symbol)
    )


def _extract_name_refs(node: ast.AST) -> set[str]:
    refs: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            refs.add(child.id)
    return refs


def _ordered_nodes(tree: ast.AST, node_type: type[ast.AST]) -> list[ast.AST]:
    nodes = [node for node in ast.walk(tree) if isinstance(node, node_type)]
    return sorted(nodes, key=lambda item: (getattr(item, "lineno", 0), getattr(item, "col_offset", 0)))


def _query_transport_from_expr(expr: ast.AST, issued_vars: set[str]) -> tuple[str, str] | None:
    text = ast.dump(expr, include_attributes=False).lower()
    if "/s/" in text or "/share/" in text:
        return None
    query_key = _query_key_from_text(text)
    if query_key is None or _is_non_finding_param(query_key):
        return None
    refs = _extract_name_refs(expr)
    matched = next((name for name in refs if name in issued_vars), None)
    if matched is None:
        return None
    kind = "query_fstring"
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        kind = "query_concatenation"
    elif isinstance(expr, ast.Call):
        symbol = _call_symbol(expr).lower()
        if symbol.endswith(".format"):
            kind = "query_format"
        elif symbol.endswith("urlencode"):
            kind = "query_urlencode"
    return matched, kind


def _is_url_builder_symbol(symbol: str) -> bool:
    lowered = symbol.lower()
    return any(token in lowered for token in ("url", "redirect", "link"))


def _resolve_query_key(text: str, token_var: str) -> str:
    return _query_key_from_text(text) or token_var


def _js_or_template_query_transport_findings(rel: str, text: str) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    issued_vars: set[str] = set()
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        lower = line.lower()
        issue_match = re.search(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([a-zA-Z0-9_$.]+)\(", line)
        if issue_match:
            var_name = issue_match.group(1)
            callee = issue_match.group(2).lower()
            if re.search(r"(create|generate|issue).*(token|invite|share|public)", callee):
                issued_vars.add(var_name)
        if "?" not in line:
            continue
        query_key = _query_key_from_text(lower)
        if query_key is None or _is_non_finding_param(query_key):
            continue
        token_var = next((var for var in issued_vars if re.search(rf"\b{re.escape(var)}\b", line)), None)
        if token_var is None:
            continue
        if any(term in lower for term in ("location.href", "window.location", "fetch(", "history.pushstate", "href=", "redirect")):
            sev, reason = _severity_from_entry(lower)
            findings.append(
                {
                    "type": _URL_CAPABILITY_RULE_ID,
                    "file": rel,
                    "line": idx,
                    "confidence": "high",
                    "message": _URL_CAPABILITY_MESSAGE,
                    "subtype": _subtype_for_name(query_key),
                    "token_variable": token_var,
                    "issuer_symbol": "js_or_template_issuer",
                    "transport_kind": "query",
                    "severity": sev,
                    "severity_reason": reason,
                    "remediation": "Prefer flash/session PRG or XHR create + DOM-only reveal.",
                }
            )
    return findings


def _python_findings(rel: str, rel_lower: str, text: str) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    if _is_doc_or_fixture_context(rel):
        return findings
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return findings
    source_lines = text.splitlines()
    assignments = _collect_string_assignments(tree)
    parent_map: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_map[child] = parent
    sqlalchemy_text_symbols, sqlalchemy_module_symbols = _sqlalchemy_import_context(tree)

    def _enclosing_function(node: ast.AST) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        current = parent_map.get(node)
        while current is not None:
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current
            current = parent_map.get(current)
        return None

    issued_vars: set[str] = set()
    issued_or_alias: set[str] = set()
    issued_by: dict[str, str] = {}
    issued_context: dict[str, str] = {}
    dict_query_vars: dict[str, tuple[str, str]] = {}
    encoded_query_vars: dict[str, tuple[str, str]] = {}
    url_vars: dict[str, tuple[str, str]] = {}
    helper_url_vars: dict[str, tuple[str, str]] = {}
    for node in _ordered_nodes(tree, ast.Assign):
        if isinstance(node, ast.Assign):
            if _is_capability_issuer_call(node.value):
                symbol = _call_symbol(node.value) or "issuer_helper"
                assign_context = source_lines[node.lineno - 1] if 0 <= node.lineno - 1 < len(source_lines) else ""
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        issued_vars.add(target.id)
                        issued_or_alias.add(target.id)
                        issued_by[target.id] = symbol
                        issued_context[target.id] = assign_context
            elif isinstance(node.value, ast.Call):
                symbol = _call_symbol(node.value).lower()
                if re.search(r"(create|generate|issue)_[a-z0-9_]*(token|invite|share|public_link|api_key|session)", symbol):
                    assign_context = source_lines[node.lineno - 1] if 0 <= node.lineno - 1 < len(source_lines) else ""
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            issued_vars.add(target.id)
                            issued_or_alias.add(target.id)
                            issued_by[target.id] = symbol
                            issued_context[target.id] = assign_context
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                if isinstance(node.value, ast.Name) and node.value.id in issued_or_alias:
                    issued_or_alias.add(target.id)
                    issued_by[target.id] = issued_by.get(node.value.id, "issuer_alias")
                    issued_context[target.id] = issued_context.get(node.value.id, "")
                if isinstance(node.value, ast.Dict):
                    keys = node.value.keys
                    values = node.value.values
                    for key_node, value_node in zip(keys, values):
                        if not isinstance(key_node, ast.Constant) or not isinstance(key_node.value, str):
                            continue
                        key_name = str(key_node.value)
                        if _is_non_finding_param(key_name):
                            continue
                        if isinstance(value_node, ast.Name) and value_node.id in issued_or_alias:
                            dict_query_vars[target.id] = (value_node.id, key_name)
                if isinstance(node.value, ast.Call):
                    symbol = _call_symbol(node.value).lower()
                    if symbol.endswith("urlencode") and node.value.args and isinstance(node.value.args[0], ast.Name):
                        var_name = node.value.args[0].id
                        if var_name in dict_query_vars:
                            encoded_query_vars[target.id] = dict_query_vars[var_name]
                    if _is_url_builder_symbol(symbol):
                        token_arg = next(
                            (arg.id for arg in node.value.args if isinstance(arg, ast.Name) and arg.id in issued_or_alias),
                            None,
                        )
                        if token_arg is not None:
                            helper_url_vars[target.id] = (token_arg, token_arg)
                expr_text = ast.get_source_segment(text, node.value) or ast.dump(node.value, include_attributes=False)
                direct = _query_transport_from_expr(node.value, issued_or_alias)
                if direct is not None:
                    token_var, kind = direct
                    query_key = _resolve_query_key(expr_text.lower(), token_var)
                    if not _is_non_finding_param(query_key):
                        url_vars[target.id] = (token_var, query_key)
                elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                    refs = _extract_name_refs(node.value)
                    encoded_ref = next((name for name in refs if name in encoded_query_vars), None)
                    if encoded_ref is not None:
                        url_vars[target.id] = encoded_query_vars[encoded_ref]
                    else:
                        helper_ref = next((name for name in refs if name in helper_url_vars), None)
                        if helper_ref is not None:
                            url_vars[target.id] = helper_url_vars[helper_ref]

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if not isinstance(target, ast.Name) or not _variable_signal(target.id):
                    continue
                literal = _constant_secret_text(node.value)
                if literal is not None:
                    if _is_example_file(rel_lower) and _is_placeholder(literal):
                        continue
                    if _value_signal(literal):
                        signal_map = _signals(target.id, literal)
                        findings.append(
                            {
                                "type": "probable_secret_exposure",
                                "file": rel,
                                "line": node.lineno,
                                "message": f"Potential hardcoded secret literal in variable '{target.id}'.",
                                "confidence": "probable",
                                "score": 4,
                                "signals": signal_map,
                                "signal_labels": _signal_labels(signal_map),
                                "variable_name": target.id,
                                "secret_value": literal,
                            }
                        )
                    continue
                if isinstance(node.value, ast.Call) and _call_name(node.value) == "os.getenv" and len(node.value.args) >= 2:
                    default_value = _constant_secret_text(node.value.args[1])
                    if default_value is None:
                        continue
                    if _is_example_file(rel_lower) and _is_placeholder(default_value):
                        continue
                    if _value_signal(default_value):
                        signal_map = _signals(target.id, default_value)
                        findings.append(
                            {
                                "type": "probable_secret_exposure",
                                "file": rel,
                                "line": node.lineno,
                                "message": f"Potential hardcoded secret default fallback in variable '{target.id}'.",
                                "confidence": "probable",
                                "score": 4,
                                "signals": signal_map,
                                "signal_labels": _signal_labels(signal_map),
                                "variable_name": target.id,
                                "secret_value": default_value,
                            }
                        )
        if isinstance(node, ast.Call):
            call_name = _call_name(node).lower()
            candidate_expr: ast.AST | None = None
            if call_name == "redirect":
                candidate_expr = node.args[0] if node.args else None
            elif call_name == "redirectresponse":
                for kw in node.keywords:
                    if kw.arg == "url":
                        candidate_expr = kw.value
                        break
                if candidate_expr is None and node.args:
                    candidate_expr = node.args[0]
            elif call_name == "urlencode":
                candidate_expr = node
            if candidate_expr is not None:
                if isinstance(candidate_expr, ast.Name) and candidate_expr.id in url_vars:
                    token_var, query_key = url_vars[candidate_expr.id]
                    context_line = source_lines[node.lineno - 1] if 0 <= node.lineno - 1 < len(source_lines) else ""
                    sev, reason = _severity_from_entry(f"{context_line} {issued_context.get(token_var, '')}")
                    findings.append(
                        {
                            "type": _URL_CAPABILITY_RULE_ID,
                            "file": rel,
                            "line": node.lineno,
                            "confidence": "high",
                            "message": _URL_CAPABILITY_MESSAGE,
                            "subtype": _subtype_for_name(query_key),
                            "token_variable": token_var,
                            "issuer_symbol": issued_by.get(token_var, "issuer_helper"),
                            "transport_kind": "query",
                            "severity": sev,
                            "severity_reason": reason,
                            "remediation": "Prefer flash/session PRG or XHR create + DOM-only reveal.",
                        }
                    )
                    continue
                if isinstance(candidate_expr, ast.Name) and candidate_expr.id in helper_url_vars:
                    token_var, query_key = helper_url_vars[candidate_expr.id]
                    context_line = source_lines[node.lineno - 1] if 0 <= node.lineno - 1 < len(source_lines) else ""
                    sev, reason = _severity_from_entry(f"{context_line} {issued_context.get(token_var, '')}")
                    findings.append(
                        {
                            "type": _URL_CAPABILITY_RULE_ID,
                            "file": rel,
                            "line": node.lineno,
                            "confidence": "high",
                            "message": _URL_CAPABILITY_MESSAGE,
                            "subtype": _subtype_for_name(query_key),
                            "token_variable": token_var,
                            "issuer_symbol": issued_by.get(token_var, "issuer_helper"),
                            "transport_kind": "query",
                            "severity": sev,
                            "severity_reason": reason,
                            "remediation": "Prefer flash/session PRG or XHR create + DOM-only reveal.",
                        }
                    )
                    continue
                match = _query_transport_from_expr(candidate_expr, issued_or_alias)
                if match is not None:
                    token_var, _kind = match
                    expr_text = ast.get_source_segment(text, candidate_expr) or ast.dump(candidate_expr, include_attributes=False)
                    query_key = _resolve_query_key(expr_text.lower(), token_var)
                    if _is_non_finding_param(query_key):
                        continue
                    context_line = source_lines[node.lineno - 1] if 0 <= node.lineno - 1 < len(source_lines) else ""
                    sev, reason = _severity_from_entry(f"{expr_text} {context_line} {issued_context.get(token_var, '')}")
                    findings.append(
                        {
                            "type": _URL_CAPABILITY_RULE_ID,
                            "file": rel,
                            "line": node.lineno,
                            "confidence": "high",
                            "message": _URL_CAPABILITY_MESSAGE,
                            "subtype": _subtype_for_name(query_key),
                            "token_variable": token_var,
                            "issuer_symbol": issued_by.get(token_var, "issuer_helper"),
                            "transport_kind": "query",
                            "severity": sev,
                            "severity_reason": reason,
                            "remediation": "Prefer flash/session PRG or XHR create + DOM-only reveal.",
                        }
                    )
        if isinstance(node, ast.Call):
            if _is_resolved_sqlalchemy_text_call(node, sqlalchemy_text_symbols, sqlalchemy_module_symbols):
                classification = _classify_sqlalchemy_text_call(
                    node,
                    assignments=assignments,
                    func_node=_enclosing_function(node),
                )
                if classification == "UNSAFE_INTERPOLATED":
                    findings.append(
                        {
                            "type": _SQL_TEXT_FINDING_TYPE,
                            "rule_id": _SQL_TEXT_RULE_ID,
                            "file": rel,
                            "line": node.lineno,
                            "message": "sqlalchemy.text() uses interpolated SQL construction; use bound parameters.",
                            "confidence": "probable",
                            "score": 4,
                            "classification": classification,
                        }
                    )
                elif classification == "UNKNOWN_COMPLEX":
                    findings.append(
                        {
                            "type": _SQL_TEXT_REVIEW_FINDING_TYPE,
                            "rule_id": _SQL_TEXT_REVIEW_RULE_ID,
                            "file": rel,
                            "line": node.lineno,
                            "message": "sqlalchemy.text() query shape is dynamic and could not be proven safe; review construction and parameter binding.",
                            "confidence": "weak",
                            "score": 1,
                            "classification": classification,
                        }
                    )
            call_name = _call_name(node)
            sink_match = call_name == "print" or call_name.startswith("logger.") or call_name in {"json.dump", "json.dumps"}
            if sink_match:
                leaked_name = _contains_suspicious_name(node)
                if leaked_name is not None:
                    findings.append(
                        {
                            "type": "probable_secret_exposure",
                            "file": rel,
                            "line": node.lineno,
                            "message": f"Potential secret leak via sink call using '{leaked_name}'.",
                            "confidence": "probable",
                            "score": 4,
                            "signals": _signals(leaked_name, leaked_name),
                            "signal_labels": ["variable_name", "sink_exposure"],
                            "variable_name": leaked_name,
                        }
                    )
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
            leaked_name = _contains_suspicious_name(node.value)
            if leaked_name is not None:
                if _is_intentional_capability_response(node.value, leaked_name, issued_or_alias):
                    continue
                findings.append(
                    {
                        "type": "probable_secret_exposure",
                        "file": rel,
                        "line": node.lineno,
                        "message": f"Potential secret response leak containing '{leaked_name}'.",
                        "confidence": "probable",
                        "score": 4,
                        "signals": _signals(leaked_name, leaked_name),
                        "signal_labels": ["variable_name", "response_exposure"],
                        "variable_name": leaked_name,
                    }
                )
    return findings


def _signal_labels(signal_map: dict[str, object]) -> list[str]:
    labels: list[str] = []
    if bool(signal_map.get("variable_name")):
        labels.append("variable_name")
    if bool(signal_map.get("literal_assignment")):
        labels.append("literal_assignment")
    if bool(signal_map.get("entropy_signal")):
        labels.append("high_entropy")
    if bool(signal_map.get("length_signal")):
        labels.append("sufficient_length")
    if bool(signal_map.get("known_prefixes")):
        labels.append("credential_prefix")
    if bool(signal_map.get("pem_markers")):
        labels.append("pem_markers")
    if bool(signal_map.get("credential_format")):
        labels.append("credential_format")
    if labels == ["variable_name", "literal_assignment"]:
        return ["variable_name_only"]
    return labels


def _confidence_from_signals(signal_map: dict[str, object]) -> tuple[str, int]:
    if bool(signal_map.get("allowlisted_variable")):
        return "noise", 0
    has_suspicious_identifier = bool(signal_map.get("variable_name"))
    has_suspicious_value = bool(signal_map.get("credential_format")) or bool(signal_map.get("known_prefixes")) or bool(
        signal_map.get("pem_markers")
    ) or bool(signal_map.get("entropy_signal"))
    if not has_suspicious_identifier:
        return "noise", 0
    if not has_suspicious_value:
        return "noise", 0
    score = 0
    if bool(signal_map.get("variable_name")):
        score += 1
    if bool(signal_map.get("literal_assignment")):
        score += 1
    if bool(signal_map.get("entropy_signal")):
        score += 1
    if bool(signal_map.get("length_signal")):
        score += 1
    if bool(signal_map.get("known_prefixes")):
        score += 2
    if bool(signal_map.get("pem_markers")):
        score += 3
    if bool(signal_map.get("credential_format")):
        score += 2
    if score >= 4:
        return "probable", score
    if score >= 2:
        return "weak", score
    return "noise", score


class SecretsHeuristicScanner(Scanner):
    scanner_name = "secrets_heuristic"
    supported_languages = ["general"]

    def is_available(self) -> bool:
        return True

    def build_command(self, project_path: Path) -> list[str]:
        return ["internal:secrets_heuristic", str(project_path)]

    def supports_explicit_file_list(self) -> bool:
        return True

    def build_command_for_files(self, project_path: Path, files: Sequence[Path]) -> list[str]:
        return ["internal:secrets_heuristic", str(project_path), str(len(files))]

    def execute(self, project_path: Path, files: Sequence[Path] | None = None) -> ScannerCommandResult:
        start = perf_counter()
        selected = list(files) if files is not None else [path for path in project_path.rglob("*") if path.is_file()]
        findings: list[dict[str, object]] = []
        telemetry = {
            "candidates_seen": 0,
            "allowlisted": 0,
            "noise_dropped": 0,
            "probable": 0,
            "weak": 0,
        }
        for file_path in selected:
            rel = file_path.resolve().relative_to(project_path.resolve()).as_posix()
            rel_lower = rel.lower()
            if _is_ignored_file(rel):
                continue
            if any(hint in rel_lower for hint in _SENSITIVE_PATH_HINTS) and not _is_example_file(rel_lower):
                telemetry["candidates_seen"] += 1
                telemetry["weak"] += 1
                findings.append(
                    {
                        "type": "sensitive_path",
                        "file": rel,
                        "line": None,
                        "confidence": "weak",
                        "signals": {
                            "allowlisted_variable": False,
                            "variable_name": False,
                            "literal_assignment": False,
                            "entropy": 0.0,
                            "entropy_signal": False,
                            "length": 0,
                            "length_signal": False,
                            "known_prefixes": False,
                            "pem_markers": False,
                            "credential_format": False,
                        },
                        "signal_labels": ["sensitive_path_hint"],
                        "score": 2,
                        "message": "Sensitive file/path naming indicates secret storage risk.",
                    }
                )
            try:
                text = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if rel_lower.endswith(".py"):
                for line in text.splitlines():
                    match = _ASSIGNMENT_RE.search(line) or _TOKEN_ASSIGNMENT_RE.search(line)
                    if match is None:
                        continue
                    telemetry["candidates_seen"] += 1
                    if _normalize_name(match.group(1)) in _ALLOWLIST_VARIABLE_NAMES:
                        telemetry["allowlisted"] += 1
                    else:
                        telemetry["noise_dropped"] += 1
                python_findings = _python_findings(rel, rel_lower, text)
                for finding in python_findings:
                    telemetry["candidates_seen"] += 1
                    telemetry["probable"] += 1
                    findings.append(finding)
                continue
            if rel_lower.endswith((".js", ".ts", ".tsx", ".jsx", ".html", ".jinja", ".j2")) and not _is_doc_or_fixture_context(rel):
                extra = _js_or_template_query_transport_findings(rel, text)
                for finding in extra:
                    telemetry["candidates_seen"] += 1
                    telemetry["probable"] += 1
                    findings.append(finding)
            for idx, line in enumerate(text.splitlines(), start=1):
                if _KEY_LINE_RE.search(line):
                    telemetry["candidates_seen"] += 1
                    telemetry["probable"] += 1
                    signal_map = {
                        "allowlisted_variable": False,
                        "variable_name": False,
                        "literal_assignment": False,
                        "entropy": 0.0,
                        "entropy_signal": False,
                        "length": 0,
                        "length_signal": False,
                        "known_prefixes": False,
                        "pem_markers": True,
                        "credential_format": False,
                    }
                    findings.append(
                        {
                            "type": "probable_secret_exposure",
                            "file": rel,
                            "line": idx,
                            "confidence": "probable",
                            "score": 5,
                            "signals": signal_map,
                            "signal_labels": _signal_labels(signal_map),
                            "message": "PEM private key marker detected.",
                        }
                    )
                elif _CERT_LINE_RE.search(line):
                    telemetry["candidates_seen"] += 1
                    telemetry["probable"] += 1
                    signal_map = {
                        "allowlisted_variable": False,
                        "variable_name": False,
                        "literal_assignment": False,
                        "entropy": 0.0,
                        "entropy_signal": False,
                        "length": 0,
                        "length_signal": False,
                        "known_prefixes": False,
                        "pem_markers": True,
                        "credential_format": False,
                    }
                    findings.append(
                        {
                            "type": "probable_secret_exposure",
                            "file": rel,
                            "line": idx,
                            "confidence": "probable",
                            "score": 5,
                            "signals": signal_map,
                            "signal_labels": _signal_labels(signal_map),
                            "message": "PEM certificate marker detected.",
                        }
                    )
                else:
                    if _is_frontend_context_file(rel_lower) and _is_intentional_frontend_token_pattern(line):
                        telemetry["noise_dropped"] += 1
                        continue
                    match = _ASSIGNMENT_RE.search(line) or _TOKEN_ASSIGNMENT_RE.search(line)
                    if match is not None:
                        telemetry["candidates_seen"] += 1
                        variable_name = match.group(1)
                        literal_value = match.group(2)
                        if _is_example_file(rel_lower) and _is_placeholder(literal_value):
                            telemetry["noise_dropped"] += 1
                            continue
                        if not _value_signal(literal_value):
                            telemetry["noise_dropped"] += 1
                            continue
                        signal_map = _signals(variable_name, literal_value)
                        if bool(signal_map.get("allowlisted_variable")):
                            telemetry["allowlisted"] += 1
                            continue
                        confidence, score = _confidence_from_signals(signal_map)
                        if confidence == "noise":
                            telemetry["noise_dropped"] += 1
                            continue
                        finding_type = "probable_secret_exposure" if confidence == "probable" else "weak_secret_management"
                        if confidence == "probable":
                            telemetry["probable"] += 1
                        else:
                            telemetry["weak"] += 1
                        findings.append(
                            {
                                "type": finding_type,
                                "file": rel,
                                "line": idx,
                                "message": f"Potential secret assignment in variable '{variable_name}'.",
                                "confidence": confidence,
                                "score": score,
                                "signals": signal_map,
                                "signal_labels": _signal_labels(signal_map),
                                "variable_name": variable_name,
                                "secret_value": literal_value,
                            }
                        )
        duration = (perf_counter() - start) * 1000
        candidate_total = int(telemetry["candidates_seen"])
        suppressed = int(telemetry["allowlisted"] + telemetry["noise_dropped"])
        suppression_rate = round((suppressed / candidate_total) * 100.0, 2) if candidate_total else 0.0
        return ScannerCommandResult(
            command=self.build_command(project_path),
            stdout=json.dumps(
                {
                    "findings": findings,
                    "scalar_metrics": {
                        "secrets_candidates_seen": candidate_total,
                        "secrets_allowlisted": int(telemetry["allowlisted"]),
                        "secrets_noise_dropped": int(telemetry["noise_dropped"]),
                        "secrets_probable": int(telemetry["probable"]),
                        "secrets_weak": int(telemetry["weak"]),
                        "secrets_suppression_rate_percent": suppression_rate,
                    },
                },
                ensure_ascii=True,
            ),
            stderr="",
            success=True,
            duration_ms=duration,
            exit_code=0,
            metadata={
                "scalar_metrics": {
                    "secrets_candidates_seen": candidate_total,
                    "secrets_allowlisted": int(telemetry["allowlisted"]),
                    "secrets_noise_dropped": int(telemetry["noise_dropped"]),
                    "secrets_probable": int(telemetry["probable"]),
                    "secrets_weak": int(telemetry["weak"]),
                    "secrets_suppression_rate_percent": suppression_rate,
                }
            },
        )
