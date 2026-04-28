from __future__ import annotations

from datetime import datetime
from typing import Sequence

from pydantic import BaseModel, Field


class BaselineEntry(BaseModel):
    fingerprint: str = Field(min_length=1)
    accepted: bool = True
    note: str | None = None
    owner: str | None = None
    created_at: datetime
    expires_at: datetime | None = None


class BaselineDocument(BaseModel):
    entries: Sequence[BaselineEntry] = Field(default_factory=list)


class BaselineStats(BaseModel):
    gross_findings: int = Field(ge=0, default=0)
    accepted_debt: int = Field(ge=0, default=0)
    new_findings: int = Field(ge=0, default=0)
    resolved_findings: int = Field(ge=0, default=0)
    scored_findings: int = Field(ge=0, default=0)
    accepted_entries: int = Field(ge=0, default=0)
    expired_entries: int = Field(ge=0, default=0)
    expiring_soon_entries: int = Field(ge=0, default=0)
    missing_owner_entries: int = Field(ge=0, default=0)
