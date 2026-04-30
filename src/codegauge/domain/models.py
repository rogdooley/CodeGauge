from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Category(str, Enum):
    security = "security"
    typing = "typing"
    lint = "lint"
    maintainability = "maintainability"
    complexity = "complexity"
    dead_code = "dead_code"
    coverage = "coverage"
    system_parser = "system/parser"


class Language(str, Enum):
    python = "python"
    javascript = "javascript"
    typescript = "typescript"
    java = "java"
    go = "go"
    yaml = "yaml"
    dockerfile = "dockerfile"
    terraform = "terraform"
    general = "general"


class Finding(BaseModel):
    tool: str
    rule_id: str
    severity: Severity
    category: Category
    language: Language
    file: Path
    line: int | None = None
    column: int | None = None
    symbol: str | None = None
    message: str
    remediation: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    tags: Sequence[str] = Field(default_factory=list)
    security_class: str = "not_security"
    security_context: str = "non_security"
    security_impact: str = "none"
    score_weight: float = Field(ge=0.0, default=1.0)
    classification_reason: str = "default_unknown"
    classification_rule_id: str = "default_unknown"
    classification_detail: str | None = None
    raw_payload: Mapping[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    scanner_name: str
    started_at: datetime
    completed_at: datetime
    duration_ms: float
    findings: Sequence[Finding]
    metadata: Mapping[str, Any] = Field(default_factory=dict)
    success: bool = True
    error_code: str | None = None
    error: str | None = None


class ScanResultSummary(BaseModel):
    scanner_name: str
    success: bool
    error_code: str | None = None
    finding_count: int
    duration_ms: float
    metadata: Mapping[str, Any] | None = None
    stdout: str | None = None
    stderr: str | None = None
    command: Sequence[str] | None = None
    exit_code: int | None = None


class Project(BaseModel):
    name: str
    path: Path
    language_hints: Sequence[Language] = Field(default_factory=list)
    config: Mapping[str, Any] = Field(default_factory=dict)
    metadata: Mapping[str, Any] = Field(default_factory=dict)


class ScoreCard(BaseModel):
    overall_score: float
    category_scores: Mapping[Category, float]
    finding_counts: Mapping[Category, int]
    summary: str | None = None


class ScanSummary(BaseModel):
    project: str
    project_metadata: Mapping[str, Any] | None = None
    scanner_count: int
    successful_scanners: int
    failed_scanners: int
    finding_count: int
    invalid_findings: int = Field(ge=0, default=0)
    invalid_paths: int = Field(ge=0, default=0)
    parse_failures: int = Field(ge=0, default=0)
    parser_missing: int = Field(ge=0, default=0)
    scanner_failures: int = Field(ge=0, default=0)
    score_card: Mapping[str, Any] | None = None
    policy: Mapping[str, Any] | None = None
    duration_ms: float
    results: Sequence[ScanResultSummary]
