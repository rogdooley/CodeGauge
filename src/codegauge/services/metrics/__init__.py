"""Metric provider contracts and extraction service."""

from .base import FindingMetricProvider, MetricProvider, ScalarMetricProvider
from .extractor import MetricsExtractor
from .fingerprint import finding_fingerprint, normalize_finding_message

__all__ = [
    "FindingMetricProvider",
    "MetricProvider",
    "MetricsExtractor",
    "ScalarMetricProvider",
    "finding_fingerprint",
    "normalize_finding_message",
]
