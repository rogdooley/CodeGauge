from __future__ import annotations

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

_SUSPICIOUS_VARIABLE_PARTS = (
    "password",
    "passwd",
    "secret",
    "apikey",
    "api_key",
    "accesskey",
    "access_key",
    "clientsecret",
    "client_secret",
    "privatekey",
    "private_key",
    "bearer",
    "credential",
)

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
    return any(part in normalized for part in _SUSPICIOUS_VARIABLE_PARTS)


def _prefix_signal(value: str) -> bool:
    return value.startswith(_KNOWN_SECRET_PREFIXES)


def _credential_format_signal(value: str) -> bool:
    return any(pattern.search(value) for pattern in _CREDENTIAL_FORMATS)


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
    has_anchor_signal = bool(signal_map.get("variable_name")) or bool(signal_map.get("known_prefixes")) or bool(
        signal_map.get("credential_format")
    ) or bool(signal_map.get("pem_markers"))
    if not has_anchor_signal:
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
            if any(hint in rel_lower for hint in _SENSITIVE_PATH_HINTS):
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
                    match = _ASSIGNMENT_RE.search(line) or _TOKEN_ASSIGNMENT_RE.search(line)
                    if match is not None:
                        telemetry["candidates_seen"] += 1
                        variable_name = match.group(1)
                        literal_value = match.group(2)
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
