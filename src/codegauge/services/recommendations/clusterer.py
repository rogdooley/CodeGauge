from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from .models import FindingCluster


class RecommendationClusterer:
    def cluster(self, findings: Sequence[Mapping[str, Any]]) -> list[FindingCluster]:
        grouped: dict[tuple[str, str, str, str], list[Mapping[str, Any]]] = {}
        for finding in findings:
            category = str(finding.get("category") or "unknown").lower()
            rule_family = self._rule_family(str(finding.get("rule_id") or "unknown"))
            message_family = self._message_family(str(finding.get("normalized_message") or finding.get("message") or ""))
            file_pattern = self._file_pattern(str(finding.get("file") or ""))
            key = (category, rule_family, message_family, file_pattern)
            grouped.setdefault(key, []).append(finding)
        clusters = [FindingCluster(key=key, findings=tuple(value)) for key, value in grouped.items()]
        clusters.sort(key=lambda c: (c.key, self._cluster_sort_marker(c)))
        return clusters

    @staticmethod
    def _cluster_sort_marker(cluster: FindingCluster) -> tuple[int, str]:
        return (len(cluster.findings), "|".join(cluster.key))

    @staticmethod
    def _rule_family(rule_id: str) -> str:
        cleaned = rule_id.strip().lower()
        if not cleaned:
            return "unknown"
        token = re.split(r"[.:/_\-]", cleaned)[0]
        alpha = re.match(r"[a-z]+", token)
        return alpha.group(0) if alpha else token[:12]

    @staticmethod
    def _message_family(message: str) -> str:
        text = message.strip().lower()
        text = re.sub(r"\d+", "#", text)
        text = re.sub(r"['\"`].*?['\"`]", "<x>", text)
        text = re.sub(r"\s+", " ", text)
        if not text:
            return "generic"
        tokens = text.split(" ")
        return " ".join(tokens[:2])

    @staticmethod
    def _file_pattern(file_path: str) -> str:
        if not file_path:
            return "project"
        parts = PurePosixPath(file_path).parts
        if len(parts) >= 1:
            return parts[0]
        return "project"
