from __future__ import annotations

from enum import Enum
from typing import Mapping, Sequence

from pydantic import BaseModel, Field

from ..domain.models import Severity


class ScoreCategory(str, Enum):
    security = "security"
    typing = "typing"
    lint = "lint"
    maintainability = "maintainability"
    complexity = "complexity"
    dead_code = "dead_code"
    coverage = "coverage"


class Grade(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class CategoryScore(BaseModel):
    category: ScoreCategory
    score: float = Field(ge=0, le=100)
    finding_count: int = Field(ge=0)
    weight: float = Field(ge=0)
    summary: str


class NormalizedMetric(BaseModel):
    category: ScoreCategory
    severity: Severity
    count: int = Field(ge=0)
    weighted_count: float | None = Field(default=None, ge=0)
    score_hint: float = Field(ge=0)
    source: str
    scalar_name: str | None = None
    scalar_value: float | None = Field(default=None, ge=0)


class ScoreCard(BaseModel):
    overall_score: float = Field(ge=0, le=100)
    category_scores: Sequence[CategoryScore]
    grade: Grade
    finding_counts: Mapping[ScoreCategory, int]
    warnings: Sequence[str] = Field(default_factory=list)
