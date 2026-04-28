from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence

from ..domain.models import ScanResult
from ..services.metrics import finding_fingerprint
from .models import BaselineDocument, BaselineEntry, BaselineStats


@dataclass(frozen=True)
class BaselineApplication:
    filtered_results: Sequence[ScanResult]
    stats: BaselineStats


class BaselineService:
    def __init__(self, *, baseline_filename: str = "baseline.json", expiring_soon_days: int = 14) -> None:
        self.baseline_filename = baseline_filename
        self.expiring_soon_days = expiring_soon_days

    def load(self, project_root: Path) -> BaselineDocument:
        path = project_root / self.baseline_filename
        if not path.exists():
            return BaselineDocument(entries=[])
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            return BaselineDocument(entries=[BaselineEntry.model_validate(entry) for entry in payload])
        if isinstance(payload, dict):
            return BaselineDocument.model_validate(payload)
        raise ValueError("baseline.json must contain an object with 'entries' or a list of entries")

    def apply(self, results: Sequence[ScanResult], baseline: BaselineDocument) -> BaselineApplication:
        now = datetime.now(UTC)
        active_entries = self._active_entries(baseline.entries, now=now)
        expired_entries = self._expired_entries(baseline.entries, now=now)
        expiring_soon_entries = self._expiring_soon_entries(baseline.entries, now=now)
        active_fingerprints = {entry.fingerprint for entry in active_entries if entry.accepted}
        accepted_entries = [entry for entry in baseline.entries if entry.accepted]
        missing_owner_entries = [entry for entry in accepted_entries if (entry.owner or "").strip() == ""]

        filtered: list[ScanResult] = []
        gross_findings = 0
        accepted_debt = 0
        current_fingerprints: set[str] = set()

        for result in results:
            if not result.success:
                filtered.append(result)
                continue
            kept_findings = []
            for finding in result.findings:
                fingerprint = finding_fingerprint(finding, include_tool=True)
                current_fingerprints.add(fingerprint)
                gross_findings += 1
                if fingerprint in active_fingerprints:
                    accepted_debt += 1
                    continue
                kept_findings.append(finding)
            filtered.append(result.model_copy(update={"findings": kept_findings}))

        resolved = sorted(active_fingerprints - current_fingerprints)
        new_findings = gross_findings - accepted_debt
        stats = BaselineStats(
            gross_findings=gross_findings,
            accepted_debt=accepted_debt,
            new_findings=new_findings,
            resolved_findings=len(resolved),
            scored_findings=new_findings,
            accepted_entries=len(accepted_entries),
            expired_entries=len(expired_entries),
            expiring_soon_entries=len(expiring_soon_entries),
            missing_owner_entries=len(missing_owner_entries),
        )
        return BaselineApplication(filtered_results=filtered, stats=stats)

    @staticmethod
    def _active_entries(entries: Sequence[BaselineEntry], *, now: datetime | None = None) -> list[BaselineEntry]:
        reference = now or datetime.now(UTC)
        active: list[BaselineEntry] = []
        for entry in entries:
            expires_at = BaselineService._normalize_datetime(entry.expires_at)
            if expires_at is not None and expires_at <= reference:
                continue
            active.append(entry)
        return active

    @staticmethod
    def _expired_entries(entries: Sequence[BaselineEntry], *, now: datetime | None = None) -> list[BaselineEntry]:
        reference = now or datetime.now(UTC)
        expired: list[BaselineEntry] = []
        for entry in entries:
            expires_at = BaselineService._normalize_datetime(entry.expires_at)
            if expires_at is not None and expires_at <= reference:
                expired.append(entry)
        return expired

    def _expiring_soon_entries(
        self,
        entries: Sequence[BaselineEntry],
        *,
        now: datetime | None = None,
    ) -> list[BaselineEntry]:
        reference = now or datetime.now(UTC)
        expiring: list[BaselineEntry] = []
        for entry in entries:
            expires_at = self._normalize_datetime(entry.expires_at)
            if expires_at is None:
                continue
            if expires_at <= reference:
                continue
            remaining_days = (expires_at - reference).total_seconds() / 86400.0
            if remaining_days <= self.expiring_soon_days:
                expiring.append(entry)
        return expiring

    @staticmethod
    def _normalize_datetime(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value

    def active_fingerprints(self, baseline: BaselineDocument, *, now: datetime | None = None) -> set[str]:
        return {
            entry.fingerprint
            for entry in self._active_entries(baseline.entries, now=now)
            if entry.accepted
        }

    @staticmethod
    def finding_fingerprint(scan_result: ScanResult, finding_index: int) -> str:
        finding = scan_result.findings[finding_index]
        return finding_fingerprint(finding, include_tool=True)

    @staticmethod
    def build_entry_payload(
        *,
        fingerprint: str,
        accepted: bool = True,
        note: str | None = None,
        owner: str | None = None,
        created_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> dict[str, Any]:
        return BaselineEntry(
            fingerprint=fingerprint,
            accepted=accepted,
            note=note,
            owner=owner,
            created_at=created_at or datetime.now(UTC),
            expires_at=expires_at,
        ).model_dump(mode="json")
